// background.js

// URL이 로드되거나 업데이트될 때마다 이 함수가 실행됩니다.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // 탭 로딩이 완료되었는지 확인
  if (changeInfo.status === 'complete' && tab.url) {
    // 탭 URL이 www.example.com 인지 확인
    if (tab.url.includes('naver-security')) {
      setTimeout(() => {
            chrome.action.openPopup(() => {
            console.log('피싱 사이트가 감지되어 팝업을 엽니다.');
            });
      }, 5000); // 1초 지연 후 팝업 열기
    }
  }
});
