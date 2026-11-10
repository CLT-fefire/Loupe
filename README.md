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
| `find_strings(ids, query\|regex\|source_ref, scope)` | 문자열 위치와 건수. `source_ref="경로:줄"`이면 그 줄의 리터럴을 찾는다. 15바이트 이하는 `(Swift 인라인)` 줄에 명령어 즉값으로 찾은 결과(주소)를 따로 준다 |
| `secret_scan(id, scope, reveal)` | 알려진 형식의 키·토큰(AWS·Google·Slack·GitHub·Stripe 키, PEM 개인 키, JWT, URL 계정 등). 값은 가리고 `fingerprint` 로 비교한다 |
| `pair_report(a, b, rules)` | 미적용(a)·적용(b) 쌍 요약: 판정, 추가 파일, 코드 변경 여부, 바뀐 이름 수, 적용본에도 남은 키·토큰, 엔타이틀먼트. 공유용 `markdown` 포함(키 원문 없음) |
| `list_names(id, other_id, section, filter, status)` | 클래스·메서드·프로퍼티 이름. 쌍으로 주면 바뀐 이름과 보존된 이름을 나눈다 |
| `ghidra_analyze(id, binary)` / `ghidra_status` | Ghidra 분석을 백그라운드로 시작하고 상태를 본다. 상태에는 지난 분석 속도로 낸 예상 시간(`estimated_remaining_s`)이 붙는다. `ghidra_status` 는 워커가 꺼져 있으면 띄우지 않고 캐시의 완료 표시로 답한다(`worker: not_running`) |
| `search_functions` / `decompile` / `xrefs` | 분석된 바이너리에서 함수 검색, 디컴파일, 참조 추적. ObjC 셀렉터는 `objc_stub` 을 부르는 실제 함수(`callers`)까지 보여 준다 |
| `compare_function(a, b, function)` | 같은 함수를 두 ipa 에서 디컴파일해 비교한다. `names_only=true` 면 로직은 같고 이름만 바뀐 것이다 |

## 판정 규칙

`src/loupe/rules/<이름>.yaml`에 있다. LIAPP 규칙(`liapp.yaml`)은 2026-11-09 실측으로 만들었다.

- LIAPP는 `.app`에 `LIAPP.ini`·`LIAPPEgg.*` 4개 파일을 추가한다.
- ObjC/Swift 이름 일부를 같은 길이의 `zZZ…Xaaa` 꼴로 바꾼다.
- 코드(`__text`)와 문자열 리터럴은 그대로 둔다.
- 바이너리 안의 "LIAPP" 문자열은 적용 근거가 아니다. SDK는 미적용본에도 링크돼 있다.

## 주의

- **Debug 빌드**(`<실행 파일>.debug.dylib` 가 있는 경우)는 이름 분석과 `scope=main` 검색이 그 dylib 를 함께 본다. 메인 실행 파일은 껍데기이기 때문이다.
- **한글 같은 비ASCII 문자열**은 UTF-8, UTF-16LE(Mach-O `__ustring`), UTF-16BE(컴파일된 `.strings` 바이너리 plist) 세 가지 인코딩으로 모두 찾는다.
- **fat 바이너리**는 arm64 slice 만 검색한다. slice 마다 같은 문자열이 있어 두 번 세는 것을 막기 위해서다.
- **출력 크기 제한**: `find_strings` 는 파일당 최대 100만 건까지 세고 맞은 파일 목록은 200개까지 보여 준다. `ipa_diff` 의 파일 목록도 각각 200개까지 보여 주며, 전체 개수는 `*_count` 로 준다. 개수 인자(`limit`·`max_hits`·`samples`)에 음수를 넣으면 거부한다.
- **`source_ref`** 는 빈 문자열 `""` 을 버린다(모든 위치에 맞아 버린다). Swift 보간 `"a\(x)b"` 은 조각(`a`, `b`)으로 나눠 찾고, `'"'` 같은 문자 리터럴은 무시한다.
- **`decompile(function=…)`** 에서 주소는 `0x` 를 붙인다. 붙이지 않으면 이름을 먼저 찾는다(`add`·`fade` 같은 이름이 주소로 오해되지 않게).

- **15바이트 이하 Swift 문자열**은 문자열 섹션에 없고 명령어 즉값으로 들어간다(워드0 = 바이트 0..7, 워드1 = 바이트 8..14 + 맨 위 바이트 `0xE0|길이`, 비ASCII 는 `0xA0|길이`). `find_strings` 는 `__text` 의 MOVZ/MOVK·ORR 비트마스크로 두 워드를 가까이(12개 명령어 안) 만드는 곳과, 데이터 섹션의 16바이트 상수를 따로 찾아 `(Swift 인라인)` 줄에 주소를 준다. 실행 중에 조합한 문자열은 못 찾으므로 0건이 확정은 아니다. 주소는 `decompile(function="0x…")` 로 확인한다.
- **`secret_scan`** 은 형식이 알려진 값만 찾는다(`src/loupe/rules/secret_patterns.yaml`). 형식 없는 임의 문자열 키는 못 찾는다 — 2026-11-10 실측 쌍에서 하드코딩 3건 중 JWT 1건만 잡히고 18자·8자 값은 안 잡혔다. 그런 값은 `find_strings(source_ref=…)` 로 확인한다. 바이너리 plist(컴파일된 `.plist`·`.strings`)는 XML 로 바꿔서 찾고(위치의 offset 은 없다), 미디어·폰트와 64MB 넘는 리소스는 건너뛴다(`skipped_files`).
- **`find_strings`·`list_names`·`decompile` 은 찾은 값을 원문으로 돌려준다.** 결과를 외부(Confluence·메일 등)로 옮길 때 키나 토큰은 사람이 가린다. `secret_scan`·`pair_report` 는 값을 가린다(16자 이상이면 앞 4자·뒤 2자, 짧으면 길이만). 같은 값인지는 `fingerprint` 로 본다. 지문은 이 Mac 의 캐시 폴더에만 있는 키(`fingerprint.key`, 권한 0600)로 만든 HMAC 이라 밖에서 되돌릴 수 없다. 원문은 `reveal=true` 일 때만 주고, 감사 로그에 `reveal` 여부를 남긴다.
- **감사 로그**(`~/Library/Caches/Loupe/loupe.log`)에는 도구 이름, ipa id, 결과 크기, 소요 시간만 남긴다. 찾은 값은 남기지 않는다.
- 프로비저닝 프로파일의 기기 UDID 목록은 개수만 보여 준다.
- ipa를 풀 때 경로 이탈(zip slip), 심볼릭 링크, 4GB 초과 압축 폭탄을 거부한다.

## Ghidra 워커

Ghidra(JVM)는 MCP 서버와 다른 프로세스(`loupe.ghidra_worker`)에서 돈다. 같은 프로세스에서 돌리면 Ghidra 로그가 stdout으로 나가 MCP 통신(stdio)이 깨지기 때문이다. 두 프로세스는 `~/Library/Caches/Loupe/ghidra.sock`으로 통신한다. 워커는 30분 동안 쓰이지 않으면 스스로 종료한다(진행 중인 요청이나 분석이 있으면 기다린다).

- **병렬 호출**: 소켓 대기열을 128 로 늘렸고, 연결이 잠깐 거절되면 클라이언트가 다시 시도한다. 워커가 죽었다는 판단도 여러 번 거절된 뒤에만 한다.
- **워커는 하나만 뜬다.** MCP 서버가 여럿(세션 여러 개)이어도 띄울 때 파일 잠금(`ghidra.spawn.lock`)을 건다. 워커도 이미 살아 있는 워커의 소켓을 빼앗지 않는다.
- **함수 이름 색인**: 프로그램마다 처음 조회할 때 함수 이름 목록을 한 번 만들어 두고, `search_functions`·이름으로 하는 `decompile`·`xrefs(kind=symbol)` 가 이 목록을 쓴다. 프로그램을 닫으면 함께 버린다. 예전에는 호출마다 함수 11.5만 개를 JVM 에서 하나씩 꺼내 읽었다.
- **`ipa_clear`** 는 워커가 그 ipa 의 프로젝트를 열어 두고 있으면 먼저 닫는다. 분석 중이면 거부한다.
- **워커 로그**(`ghidra-worker.log`)에는 실패한 op 이름과 예외 종류만 남긴다. 검색어처럼 사용자가 넣은 값이 든 메시지는 남기지 않는다.

🔴 macOS에서는 Ghidra의 프로젝트 생성과 자동 분석이 **메인 스레드가 아니면 CPU 0%로 멈춘다**(2026-11-09 실측). 그래서 분석은 워커의 메인 스레드에서 돌리고, 소켓 서버는 별도 스레드에서 돌린다. 멈춘 것 같으면 `kill -USR1 <워커 pid>`를 보내 스택을 `ghidra-worker.log`에 남긴다.

## 환경 변수

| 변수 | 기본값 |
|:--|:--|
| `LOUPE_CACHE_DIR` | `~/Library/Caches/Loupe` |
| `LOUPE_ALLOWED_DIRS` | `~/Downloads:~/Desktop:~/Library/Developer/Xcode/Archives:/Users/Shared/Source` |
| `LOUPE_SOURCE_ROOTS` | `/Users/Shared/Source/Company` |
| `GHIDRA_INSTALL_DIR` | `/opt/homebrew/opt/ghidra/libexec` |
| `LOUPE_GHIDRA_XMX` | `8g` |
| `LOUPE_GHIDRA_IDLE` | `1800`(초) |
| `LOUPE_GHIDRA_MAX_OPEN` | `3`(메모리에 열어 둘 Ghidra 프로그램 수) |
| `LOUPE_GHIDRA_TESTS` | 없음. `1` 이면 Ghidra 통합 테스트(`tests/test_ghidra_pair.py`)를 돌린다 |
| `LOUPE_TEST_IPA_DIR` | `~/Downloads/분석 mcp 개발`(실측 쌍 회귀 테스트용) |

## 알려진 한계

- **`search_functions` 개수**: Ghidra 는 import 심볼 자리에도 가상 `EXTERNAL` 블록에 1바이트짜리 "함수"를 만든다. 재서명된 LIAPP 적용본에서는 같은 심볼이 바인딩 자리마다 생겨 수만 개로 불어난다. 그래서 기본값으로 실행 가능한 블록의 함수만 세고, 걸러 낸 수는 `excluded_non_code` 로 준다. 2026-11-09 실측: 미적용 115,770개, 적용 115,767개.
- **워커 메모리**: 열어 두는 프로그램은 `LOUPE_GHIDRA_MAX_OPEN`(기본 3)개까지다. 넘으면 가장 오래 안 쓴 것부터 닫고, 다시 필요하면 몇 초 안에 다시 연다. 쓰는 중이거나 분석 중인 것은 닫지 않는다.
- **`compare_function`** 은 b 에서 a 와 **같은 주소**의 함수를 쓴다. LIAPP 처럼 코드 배치를 바꾸지 않는 보호에만 맞다. 주소가 어긋나면 `notes` 에 적는다.
- **난독화 탐지 정확도**(2026-11-09 실측 쌍): 적용본 하나만 보고 센 수가 쌍 비교의 정답과 같다(클래스 1,475 · 메서드 8,090 · 프로퍼티 2,241). 미적용본과 프레임워크 6개의 오탐은 0이다. 이름 조각 중 하나라도 패턴에 맞으면 난독화로 본다(프로퍼티 속성 문자열 `T@"…",V_…`, 인스턴스 변수 `_…`, Swift private 구분자 포함).
- **워커 소켓**은 같은 사용자 계정만 접근할 수 있다(권한 0600). 워커는 받은 경로를 다시 검사하지 않으므로, 같은 계정의 다른 프로세스는 신뢰한다는 전제다.
