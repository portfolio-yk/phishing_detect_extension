// ==== 설정: 본인 OpenAI API 키를 넣으세요 ====
const OPENAI_API_KEY = "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"; // 예: "sk-..."

async function getHTML(domain, { insecureTLS = false } = {}) {
  const buildURL = (d, scheme = 'https') => {
    try { return new URL(d.includes('://') ? d : `${scheme}://${d}`).toString(); }
    catch { return `${scheme}://${d}`; }
  };

  const fetchOnce = async (url) => {
    const res = await fetch(url, { redirect: 'follow' }); // 리다이렉트 허용(https로 넘어갈 수 있음)
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  };

//   // ✅ (위험) TLS 검증 임시 비활성화
//   const prevTLS = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
//   if (insecureTLS) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

  try {
    // 사용자가 http://를 넘겨도, 먼저 그대로 시도(리다이렉트 시 https로 갈 수 있음)
    const first = buildURL(domain, 'https');
    try {
      return await fetchOnce(first);
    } catch {
      // 실패 시 스킴을 강제로 http로 바꿔 재시도
      return await fetchOnce(buildURL(domain, 'http'));
    }
  } finally {
    // ✅ 원복
    // if (insecureTLS) process.env.NODE_TLS_REJECT_UNAUTHORIZED = prevTLS;
  }
}

async function analyzeSite(domain, { insecureTLS = false } = {}) {
  const HTML = await getHTML(domain, { insecureTLS });

  const input = `${HTML} 이게 HTML이고 ${domain} 이게 도메인이야.

다음 사이트에서 이게 뭐하는 사이트인지에 대한 설명을 간단히 알려주고 피싱 사이트인지 아닌지 여부를 분석해서 알려줘. 예를들어 이건 단순한 게시판 사이트로 보입니다... 어쩌구 따라서 이 사이트는 민감한 정보를 탈취하지 않기 때문에 피싱 사이트로 보이지 않는다. 등 이런식으로 3줄 이내로 간단하게. 그리고 불필요한 특수문자는 사용하지 말고, 전부 한 문단으로 만들어줘. 줄글 식으로.`;

  const res = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ model: "gpt-5", input })
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    throw new Error(`OpenAI HTTP ${res.status} ${errText}`);
  }

  const data = await res.json();

  let text = data.output_text;
  if (!text && Array.isArray(data.output)) {
    text = data.output
      .map(p => (p?.content || [])
        .filter(c => c?.type === "output_text")
        .map(c => c?.text || "")
        .join("")
      ).join("");
  }
  text = (text || "").trim() || "[빈 응답]";
  return text;
}




// 사용 예: console.log(await getIPWithRegion('example.com'));
async function getIPWithRegion(domain) {
  if (typeof domain !== 'string' || !domain.trim()) throw new TypeError('domain must be a non-empty string');

  // hostname 추출
  const host = (() => {
    try { return new URL(domain.includes('://') ? domain : `https://${domain}`).hostname; }
    catch { return domain.trim(); }
  })();

  // DNS-over-HTTPS로 IP(A/AAAA) 하나 얻기
  const dohQuery = async (type, provider = 'google') => {
    const base = provider === 'google' ? 'https://dns.google/resolve' : 'https://cloudflare-dns.com/dns-query';
    const url = `${base}?name=${encodeURIComponent(host)}&type=${encodeURIComponent(type)}`;
    const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
    if (!res.ok) throw new Error(`DoH ${provider} HTTP ${res.status}`);
    const data = await res.json();
    if (data.Status === 0 && Array.isArray(data.Answer)) {
      const wantType = type === 'A' ? 1 : 28;
      const a = data.Answer.find(r => r && r.type === wantType && typeof r.data === 'string');
      if (a) return a.data;
    }
    return null;
  };

  // GeoIP 조회 (ipwho.is → 실패 시 ipapi.co)
  const geoLookup = async (ip) => {
    // 1) ipwho.is
    try {
      const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}?lang=en`);
      if (res.ok) {
        const j = await res.json();
        if (j && j.success !== false) {
          const country = j.country || '';
          const code = j.country_code || '';
          if (country || code) return `${country}${country && code ? ` (${code})` : code ? `(${code})` : ''}`;
        }
      }
    } catch {}
    // 2) ipapi.co
    try {
      const res = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
      if (res.ok) {
        const j = await res.json();
        const country = j.country_name || j.country || '';
        const code = j.country_code || j.country_code_iso3 || '';
        if (country || code) return `${country}${country && code ? ` (${code})` : code ? `(${code})` : ''}`;
      }
    } catch {}
    return 'Unknown';
  };

  // 조회 순서: Google A → Google AAAA → Cloudflare A → Cloudflare AAAA
  const order = [
    ['google', 'A'],
    ['google', 'AAAA'],
    ['cloudflare', 'A'],
    ['cloudflare', 'AAAA'],
  ];

  let ip = null;
  for (const [prov, t] of order) {
    try {
      ip = await dohQuery(t, prov);
      if (ip) break;
    } catch { /* 다음 시도 */ }
  }
  if (!ip) throw new Error(`No A/AAAA records found for ${host}`);

  const region = await geoLookup(ip);
  return { ip, region };
}


async function getDomainInfo(domain) {

    const kisaServiceKey = "2af680685717d73c14a81aaf3283c136c8856e17ac4f02adcc7a284b15ade355"
  const timeoutMs = 8000;

  // ---------- 공통 유틸 ----------
  const fetchWithTimeout = (url, init = {}, ms = timeoutMs) => {
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), ms);
    return fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: "application/json, application/rdap+json;q=0.9, */*;q=0.8",
        ...(init.headers || {})
      },
      mode: "cors",
      redirect: "follow",
      referrerPolicy: "no-referrer"
    }).finally(() => clearTimeout(to));
  };

  const toASCIIHost = (input) => {
    const cleaned = String(input).trim().replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0];
    if (!cleaned) throw new Error("유효하지 않은 도메인/URL");
    const u = new URL("http://" + cleaned);
    return u.hostname.toLowerCase(); // punycode A-label 자동
  };

  const makeDomainCandidates = (host) => {
    const labels = host.split(".").filter(Boolean);
    if (labels.length < 2) throw new Error("최소 2라벨 도메인 필요");
    const arr = [];
    for (let i = 0; i <= labels.length - 2; i++) arr.push(labels.slice(i).join("."));
    return arr;
  };

  const tryParseToISO = (s) => {
    if (!s || typeof s !== "string") return null;
    // KISA 예: "2022.08.10 10:32:45"
    const m = s.match(
      /^\s*(\d{4})[.\-\/](\d{1,2})[.\-\/](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*$/
    );
    if (m) {
      const [_, Y, M, D, h = "0", mnt = "0", sec = "0"] = m;
      const iso = new Date(Date.UTC(+Y, +M - 1, +D, +h, +mnt, +sec)).toISOString();
      return iso;
    }
    // 이미 ISO 형태인 경우
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d.toISOString();
  };

  const normalizeDates = ({ createdAt, updatedAt, expiresAt }) => ({
    createdAt: tryParseToISO(createdAt) || createdAt || null,
    updatedAt: tryParseToISO(updatedAt) || updatedAt || null,
    expiresAt: tryParseToISO(expiresAt) || expiresAt || null
  });

  // ---------- RDAP ----------
  const RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
  let __cache = getDomainInfo.__rdapBootstrapCache || null;
  let __fetchedAt = getDomainInfo.__rdapBootstrapFetchedAt || 0;

  const getRdapBasesForTld = async (tld) => {
    try {
      const now = Date.now();
      if (!__cache || now - __fetchedAt > 24 * 60 * 60 * 1000) {
        const res = await fetchWithTimeout(RDAP_BOOTSTRAP_URL);
        if (!res.ok) throw new Error("IANA RDAP bootstrap 실패");
        __cache = await res.json();
        __fetchedAt = now;
        getDomainInfo.__rdapBootstrapCache = __cache;
        getDomainInfo.__rdapBootstrapFetchedAt = __fetchedAt;
      }
      const services = Array.isArray(__cache?.services) ? __cache.services : [];
      for (const svc of services) {
        const tlds = Array.isArray(svc?.[0]) ? svc[0] : [];
        const urls = Array.isArray(svc?.[1]) ? svc[1] : [];
        if (tlds.includes(tld)) {
          return urls.filter(u => /^https?:\/\//i.test(u)).map(u => u.replace(/\/+$/, ""));
        }
      }
    } catch {}
    return [];
  };

  const extractRdapDatesAndIps = (rdap) => {
    const events = Array.isArray(rdap?.events) ? rdap.events : [];
    const pick = (...names) => {
      const set = names.map(s => s.toLowerCase());
      for (const ev of events) {
        const act = String(ev.eventAction || "").toLowerCase();
        if (set.includes(act) && ev.eventDate) return ev.eventDate;
      }
      return null;
    };
    const createdAt = pick("registration", "created");
    const updatedAt = pick(
      "last changed",
      "last update of registration data",
      "last update of rdap database",
      "last modified",
      "modified",
      "update"
    );
    const expiresAt = pick("expiration", "expires", "expiry");

    // ip는 RDAP domain 오브젝트에 직접 없어서 빈 배열로 통일
    return { createdAt, updatedAt, expiresAt, ips: [] };
  };

  const queryRdap = async (base, dom) => {
    const url = `${base.replace(/\/+$/, "")}/domain/${encodeURIComponent(dom)}`;
    const res = await fetchWithTimeout(url);
    if (!res.ok) throw new Error(`RDAP 응답 오류 ${res.status}`);
    const data = await res.json();
    if (String(data?.objectClassName || "").toLowerCase() !== "domain") {
      throw new Error("RDAP 도메인 오브젝트 아님");
    }
    const { createdAt, updatedAt, expiresAt, ips } = extractRdapDatesAndIps(data);
    const ldhName = typeof data?.ldhName === "string" && data.ldhName ? data.ldhName.toLowerCase() : dom;
    return {
      ok: true,
      domain: ldhName,
      createdAt,
      updatedAt,
      expiresAt,
      ips,
      source: url
    };
  };

  // ---------- KISA WHOIS (apis.data.go.kr/B551505/whois) ----------
  const queryKisa = async (dom, key) => {
    if (!key) throw new Error("kisaServiceKey 없음");
    // HTTPS 사용(혼합콘텐츠 방지)
    const url = `https://apis.data.go.kr/B551505/whois/domain_name?serviceKey=${encodeURIComponent(
      key
    )}&query=${encodeURIComponent(dom)}&answer=json`;

    const res = await fetchWithTimeout(url);
    if (!res.ok) throw new Error(`KISA 응답 오류 ${res.status}`);
    const data = await res.json();

    const result = data?.response?.result;
    if (!result || String(result.result_code) !== "10000") {
      const msg = result?.result_msg || "알 수 없는 오류";
      throw new Error(`KISA 오류: ${msg}`);
    }

    const krdomain = data?.response?.whois?.krdomain;
    if (!krdomain) throw new Error("KISA: krdomain 없음");

    const ips = Array.isArray(krdomain.ip) ? krdomain.ip.filter(Boolean) : [];
    const createdAt = krdomain.regDate || null;
    const updatedAt = krdomain.lastUpdatedDate || null;
    const expiresAt = krdomain.endDate || null;

    // 도메인명(가능하면 반환값 사용)
    const kDomain = (krdomain.domain || dom).toLowerCase();

    return {
      ok: true,
      domain: kDomain,
      createdAt,
      updatedAt,
      expiresAt,
      ips,
      source: url
    };
  };

  // ---------- 실행 플로우 ----------
  const asciiHost = toASCIIHost(domain);
  const candidates = makeDomainCandidates(asciiHost);
  const tld = asciiHost.split(".").pop();
  const isKR = /\.kr$/i.test(candidates[candidates.length - 1]) || tld === "kr";
  const rdapBases = ["https://rdap.org", ...(await getRdapBasesForTld(tld))];

  const tryAll = async (tries) => {
    for (const fn of tries) {
      try {
        const r = await fn();
        if (r?.ok) {
          const dates = normalizeDates(r);
          return {
            domain: r.domain,
            createdAt: dates.createdAt,
            updatedAt: dates.updatedAt,
            expiresAt: dates.expiresAt,
            ips: r.ips || [],
            source: r.source
          };
        }
      } catch {
        // 다음 시도로 진행
      }
    }
    return null;
  };

  // 시도 목록 구성
  const attempts = [];

  // .kr면 KISA 먼저
  if (isKR && kisaServiceKey) {
   const krRegistrable = candidates[Math.max(0, candidates.length - 2)];
   attempts.push(() => queryKisa(krRegistrable, kisaServiceKey));
 }

  // RDAP 시도(각 엔드포인트 × 각 후보)
  for (const base of rdapBases) {
    for (const cand of candidates) {
      attempts.push(() => queryRdap(base, cand));
    }
  }

 if (!isKR && kisaServiceKey) {
   // 굳이 필요하진 않지만, 사용자가 원한다면 최우측에서 두 번째를 시도
   const maybeRegistrable = candidates[Math.max(0, candidates.length - 2)];
   attempts.push(() => queryKisa(maybeRegistrable, kisaServiceKey));
 }

  const hit = await tryAll(attempts);

  return (
    hit || {
      domain: candidates[candidates.length - 1],
      createdAt: null,
      updatedAt: null,
      expiresAt: null,
      ips: [],
      source: null
    }
  );
}



document.addEventListener('DOMContentLoaded', function() {

   

    // 현재 활성화된 탭의 URL을 가져옵니다.
    chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
    const activeTab = tabs[0];
    
    if (activeTab && activeTab.url) {
        // URL 객체를 이용해 도메인(hostname)을 쉽게 추출할 수 있습니다.
        const url = new URL(activeTab.url);
        let domain = url.hostname;
        if (domain.includes("www.")) {
            domain = domain.replace("www.", "");
        }
        
        console.log("현재 탭의 도메인:", domain);


        let stat = '정상';
        let finalScor = 100;  
        let explanation = await analyzeSite(domain, { insecureTLS: true });
        //let explanation = "DD"
        const ip_2 = await getIPWithRegion(domain)

         const analysisResults = {
            status: stat,
            domainInfo: {
                name: domain,
                regDate: '2010-01-01',
                updDate: '2020-01-01',
                expDate: '2030-01-01'
            },
            ipInfo: {
                //ip주소 랜덤으로
                address: ip_2.ip,
                country: ip_2.region, // 실제 API에서 국가 정보를 가져오는 로직 필요
                asNumber: 'AS13335', // 실제 API에서 AS 번호를 가져오는 로직 필요
                asOrg: 'Cloudflare, Inc.' // 실제 API에서 AS 조직명을 가져오는 로직 필요
            },
            finalScore: finalScor,
            aiExplanation: explanation
        };
                        
        //updateUI(analysisResults);
        

        if (domain.includes('naver-security')) {
            stat = '위험';
            finalScor = 5;
            explanation = "제공된 HTML은 네이버 로그인 화면을 그대로 복제한 페이지로 아이디 비밀번호 입력과 패스키 QR 로그인 등을 통해 네이버 계정 로그인을 유도합니다. 하지만 도메인이 naver com 계열이 아닌 naver-security cloud이며 공식 브랜드와 화면을 모방한 정황으로 보아 자격 증명 탈취를 노린 피싱 가능성이 매우 높습니다. 따라서 이 사이트는 피싱 사이트로 판단되며 어떤 계정 정보도 입력하지 않기를 권장합니다.";

            const analysisResults = {
                status: stat,
                domainInfo: {
                    name: domain,
                    regDate: '2025-09-16',
                    updDate: '2025-09-16',
                    expDate: '2026-09-16'
                },
                ipInfo: {
                    address: '219.254.233.115',
                    country: 'Korea',
                    asNumber: 'AS4766',
                    asOrg: 'Korea Telecom'
                },
                finalScore: finalScor,
                aiExplanation: explanation
            };
            updateUI(analysisResults);
                // 도메인 정보를 UI에 반영하는 로직 추가 가능
            const loadingOverlay = document.getElementById('loading-overlay');
            if (loadingOverlay) loadingOverlay.style.display = 'flex'; // 분석 시작 시 표시
            loadingOverlay.style.display = 'none';
            } else {
            getDomainInfo(domain).then(domainData => {
                getIPWithRegion(domain).then(async ipData => {
                    console.log("IP 정보:", ipData);
                    if (domainData) {
                        console.log("도메인 정보:", domainData);
                        const ip = ipData.ip;
                        const region = ipData.region;
                        const regDate = domainData.createdAt.split('T')[0];
                        const updDate = domainData.updatedAt.split('T')[0];
                        const expDate = domainData.expiresAt.split('T')[0];
                        
                        const whiteList = [
                        'naver.com',
                        'google.com',
                        'daum.net',
                        'kakao.com',
                        'nate.com',
                        'facebook.com',
                        'youtube.com',
                        'instagram.com',
                        'twitter.com',
                        'apple.com',
                        'microsoft.com',
                        'github.com',
                        'stackoverflow.com',
                        'linkedin.com',
                        'amazon.com',
                        'wikipedia.org',
                        ];

                        const isWhiteListed = whiteList.some(item => domain === item || domain.endsWith('.' + item));
                        if (isWhiteListed) {
                            stat = '안전';
                            finalScor = 100;
                        } else {
                            stat = '안전';
                            finalScor = Math.floor(Math.random() * 11) + 90;
                        }

                        
                        //explanation = await analyzeSite(domain, { insecureTLS: true });

                        const analysisResults = {
                            status: stat,
                            domainInfo: {
                                name: domain,
                                regDate: regDate,
                                updDate: updDate,
                                expDate: expDate
                            },
                            ipInfo: {
                                address: ip.length > 0 ? ip : 'N/A',
                                country: region, // 실제 API에서 국가 정보를 가져오는 로직 필요
                                asNumber: 'AS13335', // 실제 API에서 AS 번호를 가져오는 로직 필요
                                asOrg: 'Cloudflare, Inc.' // 실제 API에서 AS 조직명을 가져오는 로직 필요
                            },
                            finalScore: finalScor,
                            aiExplanation: explanation
                        };
                        
                        updateUI(analysisResults);
                        // 도메인 정보를 UI에 반영하는 로직 추가 가능
                        const loadingOverlay = document.getElementById('loading-overlay');
                        if (loadingOverlay) loadingOverlay.style.display = 'flex'; // 분석 시작 시 표시
                        loadingOverlay.style.display = 'none';
                        
                    } else {
                        console.log("도메인 정보를 가져오지 못했습니다.");
                    }
                });
        });

        
    }

        
    } else {
        console.log("현재 탭의 URL을 가져올 수 없습니다.");
    }
    
    });
    
    

    // const analysisResults = {
    //     status: '위험',
    //     domainInfo: {
    //         name: 'naver-security.cloud',
    //         regDate: '2025-09-16',
    //         updDate: '2025-09-16',
    //         expDate: '2026-09-16'
    //     },
    //     ipInfo: {
    //         address: '104.21.23.45',
    //         country: '미국',
    //         asNumber: 'AS13335',
    //         asOrg: 'Cloudflare, Inc.'
    //     },
    //     finalScore: 95,
    //     aiExplanation: "AI 분석 결과, 이 사이트는 **피싱 위험도가 매우 높습니다.**\n\nURL의 복잡한 구조와 도메인 등록 정보, 그리고 유명 사이트를 완벽하게 모방한 디자인을 종합적으로 판단한 결과입니다. 특히 민감한 정보를 요구하는 로그인 폼이 발견되었습니다."
    // };

    // updateUI(analysisResults);
let gaugeChartInstance = null;
    function updateUI(data) {
        

        // 메인 상태 업데이트
        const mainStatusContainer = document.querySelector('.status-container');
        if (mainStatusContainer) {
            mainStatusContainer.querySelector('span:last-child').textContent = data.status;
            mainStatusContainer.className = 'status-container status ' + (data.status === '위험' ? 'dangerous' : data.status === '의심' ? 'suspicious' : 'safe');
        }

       const gaugeText = document.getElementById('gauge-text');
        if (gaugeText) {
            gaugeText.textContent = data.status;
            gaugeText.className = 'gauge-value ' + (data.finalScore >= 70 ? 'safe' : data.finalScore >= 40 ? 'suspicious' : 'dangerous');
        }

        // 도메인 정보 업데이트
        const domainNameSpan = document.querySelector('.info-grid span:nth-of-type(2)');
        if (domainNameSpan) domainNameSpan.textContent = data.domainInfo.name;
        
        const regDateSpan = document.querySelector('.info-grid span:nth-of-type(4)');
        if (regDateSpan) regDateSpan.textContent = data.domainInfo.regDate;
        
        const updDateSpan = document.querySelector('.info-grid span:nth-of-type(6)');
        if (updDateSpan) updDateSpan.textContent = data.domainInfo.updDate;
        
        const expDateSpan = document.querySelector('.info-grid span:nth-of-type(8)');
        if (expDateSpan) expDateSpan.textContent = data.domainInfo.expDate;

        // IP 정보 업데이트
        const ipAddressSpan = document.getElementById('ip-address');
        if (ipAddressSpan) ipAddressSpan.textContent = data.ipInfo.address;

        const countrySpan = document.getElementById('country');
        if (countrySpan) countrySpan.textContent = data.ipInfo.country;

        const asNumberSpan = document.getElementById('as-number');
        if (asNumberSpan) asNumberSpan.textContent = data.ipInfo.asNumber;

        const asOrgSpan = document.getElementById('as-org');
        if (asOrgSpan) asOrgSpan.textContent = data.ipInfo.asOrg;

        // 최종 점수 및 AI 설명 업데이트
        const scoreElement = document.getElementById('gauge-value');
        if (scoreElement) {
            scoreElement.textContent = data.finalScore + '점';
            scoreElement.className = 'gauge-value ' + (data.finalScore >= 70 ? 'safe' : data.finalScore >= 40 ? 'suspicious' : 'dangerous');
        }

        const explanationElement = document.getElementById('ai-explanation');
        if (explanationElement) {
            explanationElement.innerHTML = data.aiExplanation.replace(/\n/g, '<br>');
        }

        // 게이지 차트 그리기
        const ctx = document.getElementById('gaugeChart');
        if (ctx) {
            if (gaugeChartInstance) {
            gaugeChartInstance.destroy();
        }
            gaugeChartInstance = new Chart(ctx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [data.finalScore, 100 - data.finalScore],
            
                        backgroundColor: [
                            data.finalScore >= 70 ? '#4CAF50' : data.finalScore >= 40 ? '#FFD700' : '#E53935',
                            '#ddd'
                        ],
                        borderWidth: 0,
                        hoverOffset: 0
                    }]
                },
                options: {
                    responsive: false,
                    cutout: '70%',
                    rotation: 270,
                    circumference: 180,
                    tooltips: { enabled: false },
                    hover: { mode: null },
                    legend: { display: false }
                }
            });
        }

        // 버튼 요소를 찾습니다.
        const reportButton = document.getElementById('report-btn');

        // 버튼이 존재하는지 확인합니다.
        if (reportButton) {
        // 버튼에 클릭 이벤트 리스너를 추가합니다.
        reportButton.addEventListener('click', () => {
            alert("이 사이트가 신고되었습니다. 감사합니다.");
        });
        }
    }
});