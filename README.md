# Loupe

우리가 직접 빌드한 iOS ipa를 정적으로 분석하는 MCP 서버다. Claude Code가 이 서버를 통해 다음을 확인한다.

- **보호 적용 여부**: LIAPP 같은 보호 솔루션이 적용됐는지와 그 근거
- **노출 확인**: 특정 문자열, 클래스·메서드 이름이 바이너리에 보이는지
- **코드 확인**: Ghidra로 특정 함수를 디컴파일해 읽을 수 있는지

App Store에서 받은 ipa(FairPlay 암호화)는 분석할 수 없다.

## 설치

필요한 것: macOS, [uv](https://docs.astral.sh/uv/), Ghidra(`brew install ghidra`), JDK 21 이상

```bash
cd /Users/Shared/Source/Company/Loupe
uv sync
uv run pytest -q                                   # 정적 분석 테스트(빠름)
LOUPE_GHIDRA_TESTS=1 uv run pytest tests/test_ghidra_pair.py -q   # Ghidra 통합(약 15초, 분석된 캐시 필요)
```

Claude Code에 등록(사용자 범위):

```bash
claude mcp add --scope user loupe -- /Users/Shared/Source/Company/Loupe/.venv/bin/loupe
```

## 도구

| 도구 | 하는 일 |
|:--|:--|
| `ipa_open(path)` | ipa를 풀어 캐시에 넣고 id를 돌려준다. 같은 ipa(sha256)는 다시 풀지 않는다 |
| `ipa_list()` / `ipa_clear(id)` | 캐시 목록과 ipa 별 크기(압축 해제본·Ghidra 프로젝트, 분석된 바이너리) 보기 / 지우기 |
| `ipa_info(id)` | 번들 정보, 프로파일 종류, 빌드 종류 추정, 메인 바이너리 요약 |
| `protection_check(id, rules)` | 보호 적용 판정(`applied` / `partial` / `not_applied` / `unknown`)과 근거. ObjC 클래스 이름 섹션이 없으면 `unknown` |
| `ipa_diff(a, b)` | 파일·섹션·이름·엔타이틀먼트·서명 차이 |
| `pair_report(a, b, rules)` | 미적용(a)·적용(b) 쌍 요약: 판정, 추가 파일, 코드 변경 여부, 바뀐 이름 수, 적용본에도 남은 키·토큰, 엔타이틀먼트. 공유용 `markdown` 포함(키 원문 없음) |
| `find_strings(ids, query\|regex\|source_ref, scope)` | 문자열 위치와 건수. `source_ref="경로:줄"`이면 그 줄의 리터럴을 찾는다. 15바이트 이하는 `(Swift 인라인)` 줄에 따로 준다 |
| `secret_scan(id, scope, reveal)` | 형식이 알려진 키·토큰(AWS·Google·Slack·GitHub·Stripe 키, PEM 개인 키, JWT, URL 계정, plist 항목) |
| `source_secrets(id, root, reveal)` | 소스에서 비밀값 모양의 리터럴(키·비밀번호·토큰 이름 바로 뒤)을 찾아 ipa 에 들어갔는지 확인한다. 형식 없는 비밀번호·키용 |
| `list_names(id, other_id, section, filter, status)` | 클래스·메서드·프로퍼티 이름. 쌍으로 주면 바뀐 이름과 보존된 이름을 나눈다 |
| `ghidra_analyze(id, binary, profile)` / `ghidra_status` | Ghidra 분석을 백그라운드로 시작하고 상태(예상 시간 포함)를 본다. `profile=fast` 는 약 20% 빠르다 |
| `search_functions` / `decompile` / `xrefs` | 분석된 바이너리에서 함수 검색, 디컴파일, 참조 추적. ObjC 셀렉터는 `objc_stub` 을 부르는 실제 함수(`callers`)까지 보여 준다 |
| `compare_function(a, b, function)` | 같은 함수를 두 ipa 에서 디컴파일해 비교한다. `names_only=true` 면 로직은 같고 이름만 바뀐 것이다. 짝을 찾은 방법은 `matched_by` |

## 판정 규칙

`src/loupe/rules/<이름>.yaml`에 있다. LIAPP 규칙(`liapp.yaml`)은 2026-11-09 실측으로 만들었다.

- LIAPP는 `.app`에 `LIAPP.ini`·`LIAPPEgg.*` 4개 파일을 추가한다.
- ObjC/Swift 이름 일부를 같은 길이의 `zZZ…Xaaa` 꼴로 바꾼다. 이름 조각 중 하나라도 패턴에 맞으면 난독화로 본다(프로퍼티 속성 문자열 `T@"…",V_…`, 인스턴스 변수 `_…`, Swift private 구분자 포함).
- 코드(`__text`)와 문자열 리터럴은 그대로 둔다. 그래서 코드에 든 키는 적용본에서도 보인다.
- 바이너리 안의 "LIAPP" 문자열은 적용 근거가 아니다. SDK는 미적용본에도 링크돼 있다.
- 정확도(2026-11-09 실측 쌍): 적용본 하나만 보고 센 난독화 수가 쌍 비교의 정답과 같다(클래스 1,475 · 메서드 8,090 · 프로퍼티 2,241). 미적용본과 프레임워크 6개의 오탐은 0이다. 그래서 미적용본 없이 적용본 하나로도 판정할 수 있다.
- 스토어 업로드용 ipa(우리가 export 한 것)는 암호화되지 않아 똑같이 분석된다. App Store 에서 내려받은 ipa 는 FairPlay 로 암호화돼 있어 분석할 수 없다.

## 동작 방식

**문자열 찾기(`find_strings`)**
- 한글 같은 비ASCII 문자열은 UTF-8, UTF-16LE(Mach-O `__ustring`), UTF-16BE(컴파일된 `.strings`) 세 인코딩으로 찾는다. fat 바이너리는 arm64 slice 만 본다. Debug 빌드(`<실행 파일>.debug.dylib`)는 `scope=main` 에 그 dylib 를 함께 넣는다.
- 15바이트 이하 Swift 문자열은 문자열 섹션에 없고 명령어 즉값으로 들어간다. 워드0 은 바이트 0..7, 워드1 은 바이트 8..14 와 맨 위 바이트(ASCII 면 `0xE0|길이`, 아니면 `0xA0|길이`)다. `__text` 에서 MOVZ/MOVK·ORR 비트마스크로 두 워드를 12개 명령어 안에 만드는 곳과, 데이터 섹션의 16바이트 상수를 찾아 `(Swift 인라인)` 줄에 주소를 준다. 주소는 `decompile(function="0x…")` 로 확인한다.
- `source_ref` 는 빈 문자열을 버리고, Swift 보간 `"a\(x)b"` 은 조각(`a`, `b`)으로 나눠 찾는다.

**키·비밀번호 찾기**
- `secret_scan` 은 `rules/secret_patterns.yaml` 의 형식으로 찾는다. 바이너리 plist 는 XML 로 바꿔서 보고(위치 offset 은 없다), 미디어·폰트와 64MB 넘는 리소스는 건너뛴다.
- `source_secrets` 는 소스(`.m .h .mm .swift .c .cpp`, 따옴표 없는 `.xcconfig` 값 포함. 빌드 산출물·`*.framework` 폴더는 뺀다)에서 비밀 키워드(key·secret·password·token·salt·credential·auth)가 든 이름 바로 뒤의 리터럴을 모은다(`let password = …`, `let apiKey: String = …`, `#define X_KEY @"…"`, `certPassword: "…"`). 이스케이프는 `find_strings` 와 같이 푼다. 그 값이 ipa 에 들어 있는지 바이너리(바이트·UTF-16·Swift 인라인)와 리소스(바이트·UTF-16, Info.plist 같은 plist 의 문자열 값)에서 확인한다. 심볼릭 링크 파일은 열지 않는다. 문장·경로·URL·색상·이름 모양은 버리고, 문자 종류와 길이로 신뢰도(high·medium·low)를 매긴다. 2026-11-10 실측에서 `Lysn_Epic` 전체 기준 후보 33건 중 ipa 에 들어간 5건이 모두 실제 하드코딩 값이었다(오탐 0, 3.8초). 파일은 한 번씩만 읽어 값마다 찾고, 서로 다른 후보가 500개를 넘으면 나머지는 확인하지 않고 알린다(`root` 를 좁힌다).
- 두 도구 모두 값을 가린다(16자 이상이면 앞 4자·뒤 2자, 짧으면 길이만). 같은 값인지는 `fingerprint` 로 본다. 지문은 이 Mac 의 캐시 폴더에만 있는 키(`fingerprint.key`, 권한 0600)로 만든 HMAC 이다. 원문은 `reveal=true` 일 때만 주고, 감사 로그에 `reveal` 여부를 남긴다. `find_strings`·`list_names`·`decompile` 은 찾은 값을 원문으로 주므로, 외부로 옮길 때는 사람이 가린다.

**함수 짝짓기(`compare_function`)**: b 에서 짝은 이 순서로 찾는다(`matching.py`).
1. 전체 이름이, 안 되면 `::` 뒤 메서드 이름이 a·b 양쪽에서 하나뿐이면 그것으로 짝짓는다. `FUN_…`·`_OUTLINED_FUNCTION_N` 같은 생성 이름은 쓰지 않는다.
2. 같은 주소에서 시작하고 바이트 서명이 같으면 짝이다. 서명은 배치에 따라 바뀌는 오프셋(분기·ADR·ADRP·리터럴 로드, ADRP 짝의 ADD·LDR/STR 즉값)을 지운 코드 해시다(`arm64.py`).
3. 서명이 같은 함수가 a 나 b 에 여럿이면(분기 대상만 다른 thunk 묶음) 호출 대상까지 넣은 서명으로 구분한다(묶음 200개까지). 그래도 같으면 묶음 개수가 a·b 같을 때 a 묶음 안의 순서로 고른다. 크기가 같은 후보가 2만 개를 넘거나 서명 계산이 60초를 넘으면 이 단계를 건너뛴다(서명은 캐시되므로 다시 부르면 이어서 빨라진다).
4. 그래도 안 되면 같은 주소의 함수를 쓰고, 그 이유를 `notes` 에 적는다.

**Ghidra 조회**
- `search_functions` 는 실행 가능한 블록의 함수만 센다. Ghidra 는 import 심볼 자리에도 가상 `EXTERNAL` 블록에 1바이트짜리 "함수"를 만들고, 재서명된 적용본에서는 이것이 수만 개로 불어나기 때문이다. 걸러 낸 수는 `excluded_non_code` 로 준다.
- `decompile(function=…)` 에서 주소는 `0x` 를 붙인다. 붙이지 않으면 이름을 먼저 찾는다(`add` 같은 이름이 주소로 오해되지 않게).
- 분석 프로필(2026-11-10, 26.5MB 메인 바이너리 실측): `full` 546초. `fast` 438초로, Stack·Call Convention ID 분석기를 끈다. 함수·명령어·`xrefs` 는 같고, 디컴파일에 호출 규약 경고가 붙는다. 두 ipa 를 비교할 때는 같은 프로필로 분석한다(다르면 `compare_function` 이 notes 맨 앞에 알린다). 이미 분석된 바이너리를 다른 프로필로 요청하면 그때의 결과를 쓰고 `note` 로 알린다. 다시 분석하려면 `ipa_clear` 후 다시 연다.

## 주의

- **출력 크기 제한**: `find_strings` 는 파일당 최대 100만 건까지 세고 맞은 파일 목록은 200개까지 보여 준다. `ipa_diff` 의 파일 목록도 각각 200개까지이고, 전체 개수는 `*_count` 로 준다. 개수 인자(`limit`·`max_hits`·`samples`)에 음수를 넣으면 거부한다.
- **감사 로그**(`~/Library/Caches/Loupe/loupe.log`)에는 도구 이름, ipa id, 결과 크기, 소요 시간, `reveal` 여부, `source_secrets` 의 소스 폴더만 남긴다. 찾은 값은 남기지 않는다.
- 프로비저닝 프로파일의 기기 UDID 목록은 개수만 보여 준다.
- ipa를 풀 때 경로 이탈(zip slip), 심볼릭 링크, 4GB 초과 압축 폭탄을 거부한다.

## Ghidra 워커

Ghidra(JVM)는 MCP 서버와 다른 프로세스(`loupe.ghidra_worker`)에서 돈다. 같은 프로세스에서 돌리면 Ghidra 로그가 stdout으로 나가 MCP 통신(stdio)이 깨지기 때문이다. 두 프로세스는 `~/Library/Caches/Loupe/ghidra.sock`으로 통신한다. 워커는 30분 동안 쓰이지 않으면 스스로 종료한다(진행 중인 요청이나 분석이 있으면 기다린다).

- **병렬 호출**: 소켓 대기열을 128 로 늘렸고, 연결이 잠깐 거절되면 클라이언트가 다시 시도한다. 워커가 죽었다는 판단도 여러 번 거절된 뒤에만 한다.
- **워커는 하나만 뜬다.** MCP 서버가 여럿(세션 여러 개)이어도 띄울 때 파일 잠금(`ghidra.spawn.lock`)을 건다. 워커도 이미 살아 있는 워커의 소켓을 빼앗지 않는다.
- **옛 워커 교체**: 워커는 ping 에 요청 형식 버전(`config.WORKER_PROTOCOL`)을 실어 준다. 워커가 이 MCP 서버보다 옛 버전이면 `shutdown` 으로 내리고 새로 띄운다(분석·조회 중이면 내리지 않고 알린다). 워커가 더 새 버전이면 이 세션의 MCP 서버가 옛 코드로 떠 있는 것이므로, 내리지 않고 세션을 다시 시작하라고 알린다. `shutdown` 이 생기기 전 워커는 진행 중인 조회를 알 수 없어 강제로 내리지 않고, `kill <pid>` 나 30분 유휴 종료를 안내한다.
- **메모리**: 열어 두는 프로그램은 `LOUPE_GHIDRA_MAX_OPEN`(기본 3)개까지다. 넘으면 가장 오래 안 쓴 것부터 닫고, 다시 필요하면 몇 초 안에 다시 연다. 쓰는 중·여는 중·분석 중인 것은 닫지 않는다. 함수 이름 색인(프로그램당 1~2초)과 함수 서명 캐시도 프로그램과 함께 버린다.
- **인자 재검사**: 소켓은 같은 사용자 계정만 접근할 수 있다(권한 0600). 그래도 워커는 요청마다 `key`·`other_key`(`<16진수 id>/<앱 기준 상대 경로>`, `..`·빈 조각 거부)와 `ipa_id` 를 검사한다. `analyze` 는 `meta.json` 의 앱 위치에서 key 가 가리키는 바이너리와 같은 파일만 연다.
- **`ipa_clear`** 는 워커가 그 ipa 의 프로젝트를 열어 두고 있으면 먼저 닫는다. 분석 중이면 거부한다.
- **워커 로그**(`ghidra-worker.log`)에는 실패한 op 이름과 예외 종류만 남긴다. 검색어처럼 사용자가 넣은 값이 든 메시지는 남기지 않는다.

🔴 macOS에서는 Ghidra의 프로젝트 생성과 자동 분석이 **메인 스레드가 아니면 CPU 0%로 멈춘다**(2026-11-09 실측). 그래서 분석은 워커의 메인 스레드에서 돌리고, 소켓 서버는 별도 스레드에서 돌린다. 멈춘 것 같으면 `kill -USR1 <워커 pid>`를 보내 스택을 `ghidra-worker.log`에 남긴다.

## 환경 변수

| 변수 | 기본값 |
|:--|:--|
| `LOUPE_CACHE_DIR` | `~/Library/Caches/Loupe` |
| `LOUPE_ALLOWED_DIRS` | `~/Downloads:~/Desktop:~/Library/Developer/Xcode/Archives:/Users/Shared/Source` |
| `LOUPE_SOURCE_ROOTS` | `/Users/Shared/Source/Company`(`source_ref`·`source_secrets` 가 읽을 수 있는 소스 루트) |
| `GHIDRA_INSTALL_DIR` | `/opt/homebrew/opt/ghidra/libexec` |
| `LOUPE_GHIDRA_XMX` | `8g` |
| `LOUPE_GHIDRA_IDLE` | `1800`(초) |
| `LOUPE_GHIDRA_MAX_OPEN` | `3`(메모리에 열어 둘 Ghidra 프로그램 수) |
| `LOUPE_GHIDRA_TESTS` | 없음. `1` 이면 Ghidra 통합 테스트(`tests/test_ghidra_pair.py`)를 돌린다 |
| `LOUPE_TEST_IPA_DIR` | `~/Downloads/분석 mcp 개발`(실측 쌍 회귀 테스트용) |

## 알려진 한계

- **정적 분석이다.** 안티디버그·무결성 검사 같은 실행 중 보호가 동작하는지는 확인하지 못한다. 실행 중에 조합한 문자열이나 키도 찾지 못한다.
- **`compare_function`**: 코드를 바꾸는 보호(명령어 치환·제어 흐름 평탄화)로 서명이 달라지고 이름까지 난독화되면 짝을 찾지 못한다(오류로 알린다). 참조하는 데이터만 다른 쌍둥이 함수는 묶음 순서로만 구분하므로, 그 개수가 두 빌드에서 다르면 역시 짝을 찾지 못한다.
- **`source_secrets`**: 비밀 키워드가 든 이름 바로 뒤의 리터럴만 본다. 키워드 없는 이름에 담거나 조각으로 이어 붙인 값은 놓친다.
- **Ghidra 분석 시간**: 26.5MB 바이너리 기준 `full` 약 9분, `fast` 약 7분. 이보다 줄이려면 switch 분석을 꺼야 하는데, 그러면 case 블록이 해독되지 않아 `xrefs` 가 빠진다(실측 명령어 −1.6%). 그래서 줄이지 않는다.
