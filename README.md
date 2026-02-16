# 🔬 nim-process_hollowing-manual_mapping

## 🎯 Nim 언어로 구현

이 프로젝트는 **Nim 언어**로 구현되었습니다

## 📚 포함된 도구

### 1. 프로세스 할로잉 (Process Hollowing)
정상 프로세스를 생성한 후 메모리를 비우고 악성 코드를 주입하는 기법의 실제 구현

**기능:**
- 실제 프로세스를 Suspended 상태로 생성
- NtUnmapViewOfSection으로 메모리 언맵
- VirtualAllocEx로 새 메모리 할당
- WriteProcessMemory로 페이로드 쓰기
- ResumeThread로 프로세스 재개
- GUI 인터페이스 (파일 선택, 로그 표시)
- Relocation 완전 처리: 베이스 주소 재배치
- Import Table 완전 재구성: 모든 DLL 함수 주소 해결
- 스레드 컨텍스트 수정: Entry Point 정확히 설정
- 모든 PE 섹션 정확히 매핑
- 실제 실행 가능한 완전한 구현


**파일:** `process_hollowing_complete.nim`

**GUI 기능:**
- 타겟 프로세스 선택 (파일 브라우저)
- 페이로드 선택 (파일 브라우저)
- 실시간 로그 표시
- 실행/로그 지우기/도움말 버튼

### 2. Manual Mapping
LoadLibrary를 사용하지 않고 수동으로 DLL을 메모리에 매핑하는 실제 구현

**기능:**
- 실행 중인 프로세스 목록 표시
- 타겟 프로세스 열기
- DLL 파일 읽기 및 PE 파싱
- 원격 프로세스에 메모리 할당
- PE 헤더 및 섹션 매핑
- CreateRemoteThread로 DllMain 호출
- GUI 인터페이스
- Relocation 완전 처리: 모든 재배치 항목 처리
- Import Table 완전 재구성: 모든 DLL 및 함수 주소 해결
- TLS Callback 실행: DLL 초기화 콜백 실행
- 모듈 숨김 (PEB 조작): InLoadOrderModuleList에서 제거


**파일:** `manual_mapping_complete.nim`

**GUI 기능:**
- 실행 중인 프로세스 목록 (드롭다운)
- 프로세스 새로고침 버튼
- DLL 파일 선택 (파일 브라우저)
- 모듈 숨김 옵션 (체크박스)
- 실시간 로그 표시
- 실행/로그 지우기/도움말 버튼

## 🚀 설치 및 사용

### 1. Nim 설치

#### Windows (Chocolatey)
```bash
choco install nim
```

#### Windows (수동)
1. [Nim 공식 웹사이트](https://nim-lang.org/install.html) 방문
2. Windows 설치 프로그램 다운로드
3. 설치 실행 (PATH 자동 추가)

#### 설치 확인
```bash
nim --version
```

### 2. 의존성 설치
```bash
nimble install nigui winim
```

### 3. 빌드

#### GUI 버전 (권장)
```bash
build_nim.bat
```

이 스크립트는:
- Nim 설치 확인
- 의존성 자동 설치
- 두 도구 모두 빌드
- GUI 모드로 컴파일 (콘솔 창 없음)

#### 콘솔 버전 (디버깅용)
```bash
build_nim_console.bat
```

### 4. 실행

#### Process Hollowing
```bash
run_process_hollowing.bat
```

또는 직접:
```bash
process_hollowing.exe
```

#### Manual Mapping
```bash
run_manual_mapping.bat
```

또는 직접:
```bash
manual_mapping.exe
```

## 📖 사용 가이드

### Process Hollowing 사용법

1. **실행**
   - `process_hollowing.exe` 실행
   - GUI 창이 열림

2. **타겟 프로세스 선택**
   - "찾기" 버튼 클릭
   - 타겟 프로세스 선택 (예: notepad.exe)

3. **페이로드 선택**
   - "찾기" 버튼 클릭
   - 페이로드 파일 선택 (유효한 .exe 파일)

4. **실행**
   - "실행" 버튼 클릭
   - 경고 메시지 확인
   - 로그에서 진행 상황 확인

### Manual Mapping 사용법

1. **실행**
   - `manual_mapping.exe` 실행
   - GUI 창이 열림

2. **프로세스 선택**
   - "새로고침" 버튼으로 프로세스 목록 업데이트
   - 드롭다운에서 타겟 프로세스 선택

3. **DLL 선택**
   - "찾기" 버튼 클릭
   - DLL 파일 선택

4. **실행**
   - "실행" 버튼 클릭
   - 경고 메시지 확인
   - 로그에서 진행 상황 확인

## 🔧 기술적 세부사항

### Windows API 사용

#### Process Hollowing
```nim
CreateProcessW()          # 프로세스 생성
NtUnmapViewOfSection()    # 메모리 언맵
VirtualAllocEx()          # 메모리 할당
WriteProcessMemory()      # 메모리 쓰기
ResumeThread()            # 스레드 재개
```

#### Manual Mapping
```nim
OpenProcess()             # 프로세스 열기
CreateToolhelp32Snapshot() # 프로세스 목록
VirtualAllocEx()          # 메모리 할당
WriteProcessMemory()      # 메모리 쓰기
CreateRemoteThread()      # 원격 스레드 생성
```

### PE 파일 파싱
```nim
# DOS Header
let e_lfanew = cast[ptr uint32](unsafeAddr data[0x3C])[]

# NT Headers
let pe_signature = data[int(e_lfanew)..int(e_lfanew)+3]

# Optional Header
let imageSize = cast[ptr int32](unsafeAddr data[int(e_lfanew) + 0x50])[]
let entryPoint = cast[ptr int32](unsafeAddr data[int(e_lfanew) + 0x28])[]
```

### GUI 라이브러리 (nigui)
```nim
import nigui

app.init()
let window = newWindow("Title")
let button = newButton("Click")
button.onClick = proc(event: ClickEvent) = 
  echo "Clicked!"
window.show()
app.run()
```

## 🐛 문제 해결

### 일반적인 오류

#### "Nim is not installed or not in PATH"
**해결:**
- Nim 설치 확인
- 터미널 재시작
- PATH 환경 변수 확인

#### "Error: cannot open file: nigui"
**해결:**
```bash
nimble install nigui
```

#### "Error: cannot open file: winim"
**해결:**
```bash
nimble install winim
```

#### "OpenProcess 실패: Error 5"
**해결:**
- 관리자 권한으로 실행
- 시스템 프로세스는 접근 불가 (정상)

## 🧪 테스트용 예시 페이로드

`examples` 폴더에 테스트용 예시 파일들이 포함되어 있습니다.

### 포함된 파일
- `test_payload.c` - Process Hollowing용 테스트 실행 파일 소스
- `test_dll.c` - Manual Mapping용 테스트 DLL 소스
- `compile_examples.bat` - 예시 파일 컴파일 스크립트

### 예시 페이로드 사용법

#### Process Hollowing 테스트
1. `examples/test_payload.exe` 컴파일
2. Process Hollowing 프로그램 실행
3. 타겟 프로세스: `C:\Windows\System32\notepad.exe`
4. 페이로드: `examples/test_payload.exe` 선택
5. 실행 버튼 클릭
6. 메시지박스가 나타나면 성공!

#### Manual Mapping 테스트
1. `examples/test_dll.dll` 컴파일
2. Manual Mapping 프로그램 실행
3. 타겟 프로세스: 실행 중인 프로세스 선택 (예: notepad.exe)
4. DLL 파일: `examples/test_dll.dll` 선택
5. 실행 버튼 클릭
6. 메시지박스가 나타나면 성공!

### 예시 코드 설명

**test_payload.c:**
- 간단한 Windows GUI 애플리케이션
- 메시지박스를 띄워 Process Hollowing 성공 확인
- 최소한의 코드로 작성되어 디버깅이 쉬움

**test_dll.c:**
- DllMain 함수 구현
- DLL_PROCESS_ATTACH 시 메시지박스 표시
- Export 함수 포함 (TestFunction)
- Manual Mapping 성공 여부 확인 가능

### 컴파일 옵션 설명
- `-mwindows`: Windows GUI 애플리케이션으로 컴파일 (콘솔 창 없음)
- `-s`: 디버그 심볼 제거 (파일 크기 감소)
- `-O2`: 최적화 레벨 2
- `-shared`: DLL로 컴파일 (test_dll.c만 해당)

## 📚 참고했던 자료

### Nim 언어
- [Nim 공식 웹사이트](https://nim-lang.org/)
- [Nim 튜토리얼](https://nim-lang.org/docs/tut1.html)
- [Nim by Example](https://nim-by-example.github.io/)

### GUI 라이브러리
- [nigui 문서](https://github.com/trustable-code/NiGui)
- [nigui 예제](https://github.com/trustable-code/NiGui/tree/master/examples)

### Windows API
- [winim 문서](https://github.com/khchen/winim)
- [Microsoft Windows API](https://docs.microsoft.com/en-us/windows/win32/api/)

### 공격 기법
- [MITRE ATT&CK: T1055](https://attack.mitre.org/techniques/T1055/)
- [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [Manual Mapping](https://www.ired.team/offensive-security/code-injection-process-injection/manual-map-dll-injection)

### 코드 질문
- Claude
- Gemini

## ⚖️ 법적 고지

### 중요 사항
- 이 도구는 교육 및 연구 목적으로만 제작되었습니다
- 허가 없이 다른 시스템에 사용하는 것은 불법입니다
- 불법적인 사용에 대한 모든 책임은 사용자에게 있습니다
- 자신의 시스템이나 허가받은 환경에서만 사용하세요


