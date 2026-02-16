# Manual Mapping 

import nigui, os, strutils, times, sequtils, strformat
import winim/lean
import winim/inc/tlhelp32

type
  ManualMappingApp = ref object
    window: Window
    processCombo: ComboBox
    dllEntry: TextBox
    hideModuleCheck: CheckBox
    logArea: TextArea
    startButton: Button
    refreshButton: Button
    isRunning: bool

# Windows API Constants
const
  MEM_COMMIT = 0x1000
  MEM_RESERVE = 0x2000
  PAGE_EXECUTE_READWRITE = 0x40
  PROCESS_ALL_ACCESS = 0x1F0FFF
  TH32CS_SNAPPROCESS = 0x00000002
  IMAGE_REL_BASED_DIR64 = 10
  IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
  IMAGE_DIRECTORY_ENTRY_IMPORT = 1
  IMAGE_DIRECTORY_ENTRY_TLS = 9
  DLL_PROCESS_ATTACH = 1

type
  PROCESS_BASIC_INFORMATION = object
    Reserved1: PVOID
    PebBaseAddress: PVOID
    Reserved2: array[2, PVOID]
    UniqueProcessId: ULONG_PTR
    Reserved3: PVOID

proc log(app: ManualMappingApp, message: string, level: string = "INFO") =
  let timestamp = now().format("HH:mm:ss")
  let logMsg = "[" & timestamp & "] [" & level & "] " & message
  app.logArea.addLine(logMsg)
  app.logArea.scrollToBottom()

proc getProcessList(): seq[tuple[name: string, pid: DWORD]] =
  result = @[]
  
  let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snapshot == INVALID_HANDLE_VALUE:
    return
  
  var pe32: PROCESSENTRY32W
  pe32.dwSize = sizeof(PROCESSENTRY32W).DWORD
  
  if Process32FirstW(snapshot, addr pe32) != 0:
    while true:
      let name = $cast[WideCString](addr pe32.szExeFile[0])
      result.add((name: name, pid: pe32.th32ProcessID))
      
      if Process32NextW(snapshot, addr pe32) == 0:
        break
  
  CloseHandle(snapshot)

proc refreshProcesses(app: ManualMappingApp) =
  let processes = getProcessList()
  var newOptions: seq[string] = @[]
  for p in processes:
    newOptions.add(&"{p.name} (PID: {p.pid})")
  
  app.processCombo.options = newOptions
  
  if app.processCombo.options.len > 0:
    app.processCombo.index = 0

proc browseDll(app: ManualMappingApp) =
  var dialog = newOpenFileDialog()
  dialog.title = "DLL 파일 선택"
  dialog.multiple = false
  dialog.run()
  if dialog.files.len > 0:
    app.dllEntry.text = dialog.files[0]

proc readDword(data: string, offset: int): DWORD =
  if offset + 4 <= data.len:
    result = cast[ptr DWORD](unsafeAddr data[offset])[]

proc readQword(data: string, offset: int): DWORD64 =
  if offset + 8 <= data.len:
    result = cast[ptr DWORD64](unsafeAddr data[offset])[]

proc readWord(data: string, offset: int): WORD =
  if offset + 2 <= data.len:
    result = cast[ptr WORD](unsafeAddr data[offset])[]

proc readPEHeader(data: string): tuple[valid: bool, imageSize: int, entryPoint: int, numSections: int, sizeOfHeaders: int, imageBase: int64, e_lfanew: int] =
  result.valid = false
  
  if data.len < 64 or data[0..1] != "MZ":
    return
  
  result.e_lfanew = readDword(data, 0x3C).int
  
  if data.len < result.e_lfanew + 256:
    return
  
  if data[result.e_lfanew..result.e_lfanew+3] != "PE\x00\x00":
    return
  
  result.numSections = cast[ptr uint16](unsafeAddr data[result.e_lfanew + 0x06])[].int
  let optHeaderOffset = result.e_lfanew + 24
  result.imageBase = readQword(data, optHeaderOffset + 0x18).int64
  result.imageSize = readDword(data, result.e_lfanew + 0x50).int
  result.sizeOfHeaders = readDword(data, result.e_lfanew + 0x54).int
  result.entryPoint = readDword(data, result.e_lfanew + 0x28).int
  
  result.valid = true

proc processRelocations(app: ManualMappingApp, dllData: string, 
                       remoteBase: LPVOID, originalBase: int64, 
                       e_lfanew: int, hProcess: HANDLE): bool =
  app.log("STEP 6: Relocation 처리", "STEP")
  
  let relocDirOffset = e_lfanew + 0xA0
  let relocRVA = readDword(dllData, relocDirOffset)
  let relocSize = readDword(dllData, relocDirOffset + 4)
  
  if relocRVA == 0 or relocSize == 0:
    app.log("  → Relocation 정보 없음", "INFO")
    return true
  
  let delta = cast[int64](remoteBase) - originalBase
  app.log(&"  → Delta: 0x{delta.toHex}", "INFO")
  
  if delta == 0:
    app.log("  → Delta가 0이므로 Relocation 불필요", "INFO")
    return true
  
  var offset = relocRVA.int
  var processed = 0
  
  while offset < (relocRVA + relocSize).int:
    if offset + 8 > dllData.len:
      break
    
    let pageRVA = readDword(dllData, offset)
    let blockSize = readDword(dllData, offset + 4)
    
    if blockSize == 0 or blockSize < 8:
      break
    
    let numEntries = (blockSize - 8) div 2
    
    for i in 0..<numEntries:
      let entryOffset = offset + 8 + (i * 2)
      if entryOffset + 2 > dllData.len:
        break
      
      let entry = readWord(dllData, entryOffset)
      let relocType = entry shr 12
      let relocOffset = entry and 0x0FFF
      
      if relocType == 0:
        continue
      elif relocType == IMAGE_REL_BASED_DIR64:
        let targetRVA = pageRVA + relocOffset.DWORD
        var value: DWORD64
        var bytesRead: SIZE_T
        
        if ReadProcessMemory(hProcess, 
                            cast[LPVOID](cast[int](remoteBase) + targetRVA.int),
                            addr value,
                            sizeof(DWORD64).SIZE_T,
                            addr bytesRead) != 0:
          value = cast[DWORD64](cast[int64](value) + delta)
          
          var bytesWritten: SIZE_T
          discard WriteProcessMemory(hProcess,
                                    cast[LPVOID](cast[int](remoteBase) + targetRVA.int),
                                    addr value,
                                    sizeof(DWORD64).SIZE_T,
                                    addr bytesWritten)
          processed.inc
    
    offset += blockSize.int
  
  app.log(&"  - {processed}개 항목 재배치 완료", "SUCCESS")
  return true

proc processImports(app: ManualMappingApp, dllData: string,
                   remoteBase: LPVOID, e_lfanew: int, hProcess: HANDLE): bool =
  app.log("STEP 7: Import Table 완전 재구성", "STEP")
  
  let importDirOffset = e_lfanew + 0x90
  let importRVA = readDword(dllData, importDirOffset)
  
  if importRVA == 0:
    app.log("  → Import Table 없음", "INFO")
    return true
  
  var offset = importRVA.int
  var dllCount = 0
  
  while offset + 20 <= dllData.len:
    let nameRVA = readDword(dllData, offset + 12)
    let firstThunk = readDword(dllData, offset + 16)
    
    if nameRVA == 0:
      break
    
    var dllName = ""
    var nameOffset = nameRVA.int
    while nameOffset < dllData.len and dllData[nameOffset] != '\0':
      dllName.add(dllData[nameOffset])
      nameOffset.inc
    
    if dllName.len == 0:
      break
    
    app.log(&"  → {dllName} 로드", "INFO")
    
    let hModule = LoadLibraryA(dllName)
    if hModule == 0:
      app.log(&"    ⚠ {dllName} 로드 실패", "WARNING")
      offset += 20
      continue
    
    var thunkOffset = firstThunk.int
    var funcCount = 0
    
    while thunkOffset + 8 <= dllData.len:
      let thunkValue = readQword(dllData, thunkOffset)
      
      if thunkValue == 0:
        break
      
      var funcAddress: LPVOID = nil
      
      if (thunkValue.uint64 and 0x8000000000000000'u64) != 0:
        let ordinal = thunkValue.uint64 and 0xFFFF
        funcAddress = GetProcAddress(hModule, cast[LPCSTR](ordinal))
      else:
        let nameRVA = (thunkValue.uint64 and 0x7FFFFFFF).int
        if nameRVA + 2 < dllData.len:
          let hintOffset = nameRVA + 2
          
          var funcName = ""
          var fnOffset = hintOffset
          while fnOffset < dllData.len and dllData[fnOffset] != '\0':
            funcName.add(dllData[fnOffset])
            fnOffset.inc
          
          if funcName.len > 0:
            funcAddress = GetProcAddress(hModule, funcName)
      
      if funcAddress != nil:
        var bytesWritten: SIZE_T
        let iatAddress = cast[LPVOID](cast[int](remoteBase) + thunkOffset)
        
        discard WriteProcessMemory(hProcess,
                                  iatAddress,
                                  addr funcAddress,
                                  sizeof(LPVOID).SIZE_T,
                                  addr bytesWritten)
        funcCount.inc
      
      thunkOffset += 8
    
    app.log(&"    - {funcCount}개 함수 주소 해결", "SUCCESS")
    dllCount.inc
    offset += 20
  
  app.log(&"  - {dllCount}개 DLL Import 완료", "SUCCESS")
  return true

proc processTLS(app: ManualMappingApp, dllData: string,
               remoteBase: LPVOID, e_lfanew: int, hProcess: HANDLE): bool =
  app.log("STEP 8: TLS Callback 실행", "STEP")
  
  let tlsDirOffset = e_lfanew + 0xC0
  let tlsRVA = readDword(dllData, tlsDirOffset)
  
  if tlsRVA == 0:
    app.log("  → TLS Directory 없음", "INFO")
    return true
  
  if tlsRVA.int + 40 > dllData.len:
    app.log("  ⚠ TLS Directory 범위 초과", "WARNING")
    return false
  
  let addressOfCallBacks = readQword(dllData, tlsRVA.int + 24)
  
  if addressOfCallBacks == 0:
    app.log("  → TLS Callback 없음", "INFO")
    return true
  
  var callbackCount = 0
  var callbackIndex = 0
  
  while callbackIndex < 10:
    var callback: DWORD64
    var bytesRead: SIZE_T
    
    let callbackAddr = cast[LPVOID](addressOfCallBacks + (callbackIndex * 8).DWORD64)
    
    if ReadProcessMemory(hProcess, callbackAddr,
                        addr callback,
                        sizeof(DWORD64).SIZE_T,
                        addr bytesRead) == 0:
      break
    
    if callback == 0:
      break
    
    var threadId: DWORD
    let hThread = CreateRemoteThread(hProcess,
                                     nil,
                                     0,
                                     cast[LPTHREAD_START_ROUTINE](callback),
                                     remoteBase,
                                     0,
                                     addr threadId)
    
    if hThread != 0:
      discard WaitForSingleObject(hThread, 5000)
      CloseHandle(hThread)
      callbackCount.inc
      app.log(&"  - TLS Callback #{callbackIndex + 1} 실행", "SUCCESS")
    
    callbackIndex.inc
  
  if callbackCount > 0:
    app.log(&"  - {callbackCount}개 TLS Callback 실행 완료", "SUCCESS")
  
  return true

proc hideModule(app: ManualMappingApp, hProcess: HANDLE, moduleBase: LPVOID): bool =
  app.log("STEP 9: 모듈 리스트에서 숨기기 (PEB 조작)", "STEP")
  
  type NtQueryInformationProcessProc = proc(
    processHandle: HANDLE,
    processInformationClass: DWORD,
    processInformation: PVOID,
    processInformationLength: DWORD,
    returnLength: ptr ULONG
  ): NTSTATUS {.stdcall.}
  
  let ntdll = LoadLibraryA("ntdll.dll")
  if ntdll == 0:
    app.log("  ⚠ ntdll.dll 로드 실패", "WARNING")
    return false
  
  let ntQuery = cast[NtQueryInformationProcessProc](
    GetProcAddress(ntdll, "NtQueryInformationProcess")
  )
  
  if ntQuery == nil:
    FreeLibrary(ntdll)
    app.log("  ⚠ NtQueryInformationProcess 찾기 실패", "WARNING")
    return false
  
  var pbi: PROCESS_BASIC_INFORMATION
  var returnLength: ULONG
  
  let status = ntQuery(hProcess, 0, addr pbi,
                      sizeof(PROCESS_BASIC_INFORMATION).DWORD,
                      addr returnLength)
  
  FreeLibrary(ntdll)
  
  if status != 0:
    app.log("  ⚠ PEB 주소 가져오기 실패", "WARNING")
    return false
  
  var ldrAddress: PVOID
  var bytesRead: SIZE_T
  
  if ReadProcessMemory(hProcess,
                      cast[LPVOID](cast[int](pbi.PebBaseAddress) + 0x18),
                      addr ldrAddress,
                      sizeof(PVOID).SIZE_T,
                      addr bytesRead) == 0:
    app.log("  ⚠ Ldr 주소 읽기 실패", "WARNING")
    return false
  
  var listHead: PVOID
  if ReadProcessMemory(hProcess,
                      cast[LPVOID](cast[int](ldrAddress) + 0x10),
                      addr listHead,
                      sizeof(PVOID).SIZE_T,
                      addr bytesRead) == 0:
    app.log("  ⚠ InLoadOrderModuleList 읽기 실패", "WARNING")
    return false
  
  var currentEntry = listHead
  var iterations = 0
  
  while iterations < 100:
    var dllBase: PVOID
    if ReadProcessMemory(hProcess,
                        cast[LPVOID](cast[int](currentEntry) + 0x30),
                        addr dllBase,
                        sizeof(PVOID).SIZE_T,
                        addr bytesRead) == 0:
      break
    
    if dllBase == moduleBase:
      var flink, blink: PVOID
      
      if ReadProcessMemory(hProcess, currentEntry, addr flink, 
                          sizeof(PVOID).SIZE_T, addr bytesRead) != 0 and
         ReadProcessMemory(hProcess, cast[LPVOID](cast[int](currentEntry) + 8), 
                          addr blink, sizeof(PVOID).SIZE_T, addr bytesRead) != 0:
        
        discard WriteProcessMemory(hProcess, cast[LPVOID](cast[int](flink) + 8), 
                                  addr blink, sizeof(PVOID).SIZE_T, nil)
        discard WriteProcessMemory(hProcess, blink, addr flink, 
                                  sizeof(PVOID).SIZE_T, nil)
        
        app.log("  - InLoadOrderModuleList에서 제거", "SUCCESS")
        app.log("  - 모듈 숨김 완료", "SUCCESS")
        return true
    
    var nextEntry: PVOID
    if ReadProcessMemory(hProcess, currentEntry, addr nextEntry, 
                        sizeof(PVOID).SIZE_T, addr bytesRead) == 0:
      break
    
    if nextEntry == listHead:
      break
    
    currentEntry = nextEntry
    iterations.inc
  
  app.log("  ⚠ 모듈을 리스트에서 찾지 못함", "WARNING")
  return false

proc runMapping(app: ManualMappingApp) =
  let processStr = app.processCombo.value
  let dllPath = app.dllEntry.text
  
  if processStr == "":
    app.log("타겟 프로세스를 선택하세요.", "ERROR")
    return
  
  if not fileExists(dllPath):
    app.log("DLL 파일을 찾을 수 없습니다: " & dllPath, "ERROR")
    return
  
  var pid: DWORD = 0
  try:
    let parts = processStr.split("PID: ")
    if parts.len >= 2:
      pid = parts[1].strip(chars = {')'}).parseInt().DWORD
  except:
    app.log("프로세스 ID를 추출할 수 없습니다.", "ERROR")
    return
  
  app.isRunning = true
  app.startButton.enabled = false
  
  try:
    app.log("=" & repeat("=", 79), "INFO")
    app.log("Manual Mapping 시작", "INFO")
    app.log("=" & repeat("=", 79), "INFO")
    app.log(&"타겟 PID: {pid}", "INFO")
    app.log(&"DLL: {dllPath}", "INFO")
    app.log("", "INFO")
    
    app.log("STEP 1: 타겟 프로세스 열기", "STEP")
    
    let hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
    if hProcess == 0:
      let error = GetLastError()
      raise newException(OSError, &"OpenProcess 실패: Error {error} (관리자 권한 필요할 수 있음)")
    
    app.log(&"  - 프로세스 핸들 획득: {hProcess}", "SUCCESS")
    app.log("", "INFO")
    
    app.log("STEP 2: DLL 파일 읽기 및 파싱", "STEP")
    
    let dllData = readFile(dllPath)
    app.log(&"  - DLL 크기: {dllData.len} bytes", "SUCCESS")
    
    let peInfo = readPEHeader(dllData)
    if not peInfo.valid:
      raise newException(ValueError, "유효하지 않은 PE 파일입니다")
    
    app.log("  - DOS 헤더 확인", "SUCCESS")
    app.log("  - NT 헤더 확인", "SUCCESS")
    app.log(&"  - 이미지 크기: {peInfo.imageSize} bytes", "SUCCESS")
    app.log(&"  - 섹션 개수: {peInfo.numSections}", "SUCCESS")
    app.log("", "INFO")
    
    app.log("STEP 3: 타겟 프로세스에 메모리 할당", "STEP")
    
    let remoteBase = VirtualAllocEx(
      hProcess,
      nil,
      peInfo.imageSize.SIZE_T,
      MEM_COMMIT or MEM_RESERVE,
      PAGE_EXECUTE_READWRITE
    )
    
    if remoteBase == nil:
      raise newException(OSError, "VirtualAllocEx 실패")
    
    app.log(&"  - 메모리 할당 성공: 0x{cast[int](remoteBase).toHex}", "SUCCESS")
    app.log(&"  - 크기: {peInfo.imageSize} bytes", "SUCCESS")
    app.log("", "INFO")
    
    app.log("STEP 4: PE 헤더 쓰기", "STEP")
    
    var bytesWritten: SIZE_T
    let writeResult = WriteProcessMemory(
      hProcess,
      remoteBase,
      unsafeAddr dllData[0],
      peInfo.sizeOfHeaders.SIZE_T,
      addr bytesWritten
    )
    
    if writeResult == 0:
      raise newException(OSError, "WriteProcessMemory (헤더) 실패")
    
    app.log(&"  - 헤더 쓰기 완료: {bytesWritten} bytes", "SUCCESS")
    app.log("", "INFO")
    
    app.log("STEP 5: 섹션 매핑", "STEP")
    
    let optHeaderSize = cast[ptr uint16](unsafeAddr dllData[peInfo.e_lfanew + 0x14])[]
    let sectionHeaderOffset = peInfo.e_lfanew + 24 + int(optHeaderSize)
    
    for i in 0..<peInfo.numSections:
      let sectionOffset = sectionHeaderOffset + (i * 40)
      if sectionOffset + 40 > dllData.len:
        break
      
      var sectionName = ""
      for j in 0..<8:
        let c = dllData[sectionOffset + j]
        if c != '\0':
          sectionName.add(c)
      
      let virtualSize = readDword(dllData, sectionOffset + 8).int
      let virtualAddress = readDword(dllData, sectionOffset + 12).int
      let rawSize = readDword(dllData, sectionOffset + 16).int
      let rawOffset = readDword(dllData, sectionOffset + 20).int
      
      if rawSize > 0 and rawOffset + rawSize <= dllData.len:
        let writeAddr = cast[LPVOID](cast[int](remoteBase) + virtualAddress)
        let result = WriteProcessMemory(
          hProcess,
          writeAddr,
          unsafeAddr dllData[rawOffset],
          rawSize.SIZE_T,
          addr bytesWritten
        )
        
        if result != 0:
          app.log(&"  - {sectionName} -> 0x{cast[int](writeAddr).toHex} ({bytesWritten} bytes)", "SUCCESS")
        else:
          app.log(&"  - {sectionName} 쓰기 실패", "WARNING")
    
    app.log("", "INFO")
    
    if not processRelocations(app, dllData, remoteBase, peInfo.imageBase, peInfo.e_lfanew, hProcess):
      app.log("  ⚠ Relocation 처리 실패", "WARNING")
    app.log("", "INFO")
    
    if not processImports(app, dllData, remoteBase, peInfo.e_lfanew, hProcess):
      app.log("  ⚠ Import Table 재구성 실패", "WARNING")
    app.log("", "INFO")
    
    if not processTLS(app, dllData, remoteBase, peInfo.e_lfanew, hProcess):
      app.log("  ⚠ TLS Callback 실행 실패", "WARNING")
    app.log("", "INFO")
    
    app.log("STEP 10: DllMain 호출", "STEP")
    
    let entryPoint = cast[LPTHREAD_START_ROUTINE](cast[int](remoteBase) + peInfo.entryPoint)
    app.log(&"  → Entry Point: 0x{cast[int](entryPoint).toHex}", "INFO")
    
    var threadId: DWORD
    let hThread = CreateRemoteThread(
      hProcess,
      nil,
      0,
      entryPoint,
      remoteBase,
      0,
      addr threadId
    )
    
    if hThread != 0:
      app.log(&"  - 원격 스레드 생성 성공 (TID: {threadId})", "SUCCESS")
      app.log("  - DllMain 호출 시도", "SUCCESS")
      
      discard WaitForSingleObject(hThread, 5000)
      CloseHandle(hThread)
    else:
      app.log("  ⚠ CreateRemoteThread 실패", "WARNING")
      app.log("  → DllMain이 호출되지 않았을 수 있습니다", "WARNING")
    
    app.log("", "INFO")
    
    if app.hideModuleCheck.checked:
      if not hideModule(app, hProcess, remoteBase):
        app.log("  ⚠ 모듈 숨김 실패", "WARNING")
      app.log("", "INFO")
    
    CloseHandle(hProcess)
    
    app.log("=" & repeat("=", 79), "INFO")
    app.log("Manual Mapping 완료!", "SUCCESS")
    app.log("=" & repeat("=", 79), "INFO")
    
  except Exception as e:
    app.log("오류 발생: " & e.msg, "ERROR")
    app.log(e.getStackTrace(), "ERROR")
  finally:
    app.isRunning = false
    app.startButton.enabled = true

proc startMapping(app: ManualMappingApp) =
  if app.isRunning:
    app.window.alert("이미 실행 중입니다.")
    return
  
  # Simple confirmation - just run it
  runMapping(app)

proc clearLog(app: ManualMappingApp) =
  app.logArea.text = ""

proc showHelp(app: ManualMappingApp) =
  app.window.alert(
    "Manual Mapping\n\n" &
    "구현된 기능:\n" &
    "- 타겟 프로세스 열기\n" &
    "- DLL 파일 읽기 및 PE 파싱\n" &
    "- 메모리 할당\n" &
    "- PE 헤더 쓰기\n" &
    "- 섹션 매핑\n" &
    "- Relocation 완전 처리\n" &
    "- Import Table 완전 재구성\n" &
    "- TLS Callback 실행\n" &
    "- DllMain 호출\n" &
    "- 모듈 숨김 (PEB 조작)\n\n" &
    "vs LoadLibrary:\n" &
    "- LoadLibrary: 시스템 API 사용, 탐지 쉬움\n" &
    "- Manual Mapping: 수동 매핑, 탐지 어려움\n\n" &
    "중요 사항:\n" &
    "- 관리자 권한 필요\n" &
    "- 안티바이러스가 탐지할 수 있음\n" &
    "- 타겟 프로세스가 충돌할 수 있음\n\n" &
    "법적 책임:\n" &
    "불법적인 사용에 대한 모든 책임은 사용자에게 있습니다.",
    "도움말"
  )

proc createUI(): ManualMappingApp =
  result = ManualMappingApp()
  result.isRunning = false
  
  app.init()
  
  result.window = newWindow("Manual Mapping")
  result.window.width = 900.scaleToDpi
  result.window.height = 700.scaleToDpi
  
  let container = newLayoutContainer(Layout_Vertical)
  result.window.add(container)
  
  let titleLabel = newLabel("Manual Mapping")
  titleLabel.fontSize = 16
  container.add(titleLabel)
  
  let configFrame = newLayoutContainer(Layout_Vertical)
  container.add(configFrame)
  
  let processLabel = newLabel("타겟 프로세스:")
  processLabel.widthMode = WidthMode_Static
  processLabel.width = 120.scaleToDpi
  configFrame.add(processLabel)
  
  let processContainer = newLayoutContainer(Layout_Horizontal)
  configFrame.add(processContainer)
  result.processCombo = newComboBox()
  processContainer.add(result.processCombo)
  result.refreshButton = newButton("새로고침")
  result.refreshButton.widthMode = WidthMode_Static
  result.refreshButton.width = 100.scaleToDpi
  let appRef = result  # Create a reference for closure
  result.refreshButton.onClick = proc(event: ClickEvent) = appRef.refreshProcesses()
  processContainer.add(result.refreshButton)
  
  let dllLabel = newLabel("DLL 파일:")
  dllLabel.widthMode = WidthMode_Static
  dllLabel.width = 120.scaleToDpi
  configFrame.add(dllLabel)
  
  let dllContainer = newLayoutContainer(Layout_Horizontal)
  configFrame.add(dllContainer)
  result.dllEntry = newTextBox()
  result.dllEntry.text = "payload.dll"
  dllContainer.add(result.dllEntry)
  let dllBtn = newButton("찾기")
  dllBtn.widthMode = WidthMode_Static
  dllBtn.width = 80.scaleToDpi
  dllBtn.onClick = proc(event: ClickEvent) = appRef.browseDll()
  dllContainer.add(dllBtn)
  
  result.hideModuleCheck = newCheckBox("모듈 리스트에서 숨기기 (PEB 조작)")
  configFrame.add(result.hideModuleCheck)
  
  let logLabel = newLabel("실행 로그:")
  container.add(logLabel)
  
  result.logArea = newTextArea()
  result.logArea.editable = false
  result.logArea.height = 400.scaleToDpi
  container.add(result.logArea)
  
  let buttonContainer = newLayoutContainer(Layout_Horizontal)
  container.add(buttonContainer)
  
  result.startButton = newButton("실행")
  result.startButton.onClick = proc(event: ClickEvent) = appRef.startMapping()
  buttonContainer.add(result.startButton)
  
  let clearBtn = newButton("로그 지우기")
  clearBtn.onClick = proc(event: ClickEvent) = appRef.clearLog()
  buttonContainer.add(clearBtn)
  
  let helpBtn = newButton("도움말")
  helpBtn.onClick = proc(event: ClickEvent) = appRef.showHelp()
  buttonContainer.add(helpBtn)
  
  result.refreshProcesses()

when isMainModule:
  let myApp = createUI()
  myApp.window.show()
  app.run()
