import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import BertTokenizer, BertModel
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pandas as pd
import numpy as np
import geoiplite  # IP 정보 조회를 위한 라이브러리
import datetime

# IP 데이터베이스 다운로드
geoiplite.init() 

# 1. 데이터셋 생성 (예제 데이터)
# 실제로는 여러분의 HTML 텍스트, IP 정보, 레이블을 포함하는 CSV/JSON 파일을 사용해야 합니다.
data = {
    'html_text': [
        '<html><body><h1>Welcome to My Bank</h1><p>Please login to view your account.</p></body></html>',
        '<html><body><h1>You have a new message!</h1><p>Click here to login: <a href="http://phishing-site.com">Login</a></p></body></html>',
        '<html><body><h1>Important security update</h1><p>We detected unusual activity. Verify your identity: <a href="http://malware-site.com">Click here</a></p></body></html>',
        '<html><body><h1>Your PayPal account has been limited</h1><p>Click here to restore full access: <a href="http://phishing-paypal.com">Restore</a></p></body></html>',
        '<html><body><h1>Shop now at our new online store!</h1><p>Great deals and new products!</p></body></html>',
        '<html><body><h1>Your delivery has been delayed</h1><p>Enter your details to reschedule delivery: <a href="http://data-collection.net">Reschedule</a></p></body></html>'
    ],
    'ip_info': [
        '203.0.113.1',
        '198.51.100.1',
        '203.0.113.2',
        '192.0.2.1',
        '203.0.113.3',
        '198.51.100.2'
    ],
    # 예제 데이터에 임의의 등록일을 추가 (실제로는 whois 등을 통해 얻어야 함)
    'registration_date': [
        datetime.date(2010, 1, 1),
        datetime.date(2025, 8, 20),
        datetime.date(2024, 5, 10),
        datetime.date(2025, 8, 21),
        datetime.date(2012, 6, 15),
        datetime.date(2025, 8, 19)
    ],
    'is_phishing': [0, 1, 1, 1, 0, 1],
    'phishing_type': ['normal', 'payment', 'malware', 'payment', 'normal', 'data_collection']
}
df = pd.DataFrame(data)

# 레이블을 숫자로 변환
label_map = {'normal': 0, 'payment': 1, 'malware': 2, 'data_collection': 3}
df['phishing_type_label'] = df['phishing_type'].map(label_map)


# IP 정보에서 특징 추출 및 매핑
def extract_ip_features(ip, registration_date):
    try:
        reader = geoiplite.open('GeoLite2-City.mmdb')
        lookup = reader.lookup(ip)
        
        # 지리적 정보
        country = lookup.country.name
        asn = lookup.asn
        
        # 등록일로부터 경과한 일수 계산
        today = datetime.date.today()
        days_since_reg = (today - registration_date).days

        return {
            'country': country,
            'asn': asn,
            'days_since_reg': days_since_reg
        }
    except Exception:
        # 정보 조회 실패 시 기본값 반환
        return {
            'country': 'unknown',
            'asn': 0, # ASN 0은 보통 예약된 값 또는 unknown을 의미
            'days_since_reg': 0
        }

# 데이터프레임에 IP 특징 추가
df_ip_features = df.apply(lambda row: extract_ip_features(row['ip_info'], row['registration_date']), axis=1)
df['country'] = [f['country'] for f in df_ip_features]
df['asn'] = [f['asn'] for f in df_ip_features]
df['days_since_reg'] = [f['days_since_reg'] for f in df_ip_features]


# 범주형 데이터를 정수 ID로 매핑
def create_label_maps(df, columns):
    maps = {}
    for col in columns:
        unique_vals = df[col].unique()
        maps[col] = {val: i for i, val in enumerate(unique_vals)}
        if 'unknown' not in maps[col]:
            maps[col]['unknown'] = len(maps[col])
    return maps

categorical_cols = ['country']
label_maps = create_label_maps(df, categorical_cols)

# 매핑된 정수 ID로 데이터 변환
df['country_id'] = df['country'].map(label_maps['country'])
df['asn_id'] = df['asn'].astype('category').cat.codes.tolist()
# NOTE: ASN은 매우 많은 값을 가질 수 있으므로, 범주형으로 처리하는 것이 더 일반적입니다.
# 여기서는 간단하게 pandas의 .cat.codes를 사용했습니다.

# 2. 확장된 데이터셋 클래스
class PhishingDataset(Dataset):
    def __init__(self, df, tokenizer, max_len, label_maps):
        self.df = df
        self.tokenizer = tokenizer
        self.max_len = max_len
        self.label_maps = label_maps

    def __len__(self):
        return len(self.df)

    def __getitem__(self, item):
        row = self.df.iloc[item]
        
        # BERT 토크나이징
        encoding = self.tokenizer.encode_plus(
            str(row['html_text']),
            add_special_tokens=True,
            max_length=self.max_len,
            return_token_type_ids=False,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt',
        )
        
        # 수치형 IP 정보 (등록일)
        days_since_reg_tensor = torch.tensor(row['days_since_reg'], dtype=torch.float).unsqueeze(0)
        
        # 범주형 IP 정보 (국가 ID, ASN ID)
        country_id_tensor = torch.tensor(row['country_id'], dtype=torch.long)
        asn_id_tensor = torch.tensor(row['asn_id'], dtype=torch.long)

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'days_since_reg': days_since_reg_tensor,
            'country_id': country_id_tensor,
            'asn_id': asn_id_tensor,
            'is_phishing_label': torch.tensor(row['is_phishing'], dtype=torch.long),
            'phishing_type_label': torch.tensor(row['phishing_type_label'], dtype=torch.long)
        }

# 3. 확장된 모델 정의: Bert와 IP 정보를 결합
class PhishingClassifier(nn.Module):
    def __init__(self, n_is_phishing_classes, n_phishing_type_classes, bert_model_name,
                 num_countries, num_asns,
                 country_embedding_dim=16, asn_embedding_dim=32):
        super(PhishingClassifier, self).__init__()
        self.bert = BertModel.from_pretrained(bert_model_name)
        bert_output_dim = self.bert.config.hidden_size
        
        # IP 관련 임베딩 레이어
        self.country_embedding = nn.Embedding(num_embeddings=num_countries + 1, embedding_dim=country_embedding_dim)
        self.asn_embedding = nn.Embedding(num_embeddings=num_asns, embedding_dim=asn_embedding_dim)

        # IP 수치형 데이터 처리 레이어 (등록일)
        ip_numeric_dim = 1 # days_since_reg
        self.ip_numeric_fc = nn.Linear(ip_numeric_dim, 16)
        
        # 결합된 피처를 위한 레이어
        combined_features_dim = (
            bert_output_dim + 
            country_embedding_dim + 
            asn_embedding_dim + 
            16
        )
        
        self.dropout = nn.Dropout(0.3)
        self.fc1_is_phishing = nn.Linear(combined_features_dim, n_is_phishing_classes)
        self.fc2_phishing_type = nn.Linear(combined_features_dim, n_phishing_type_classes)

    def forward(self, input_ids, attention_mask, days_since_reg, country_id, asn_id):
        # Bert 임베딩
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        bert_output = outputs['pooler_output']

        # IP 정보 처리
        country_emb = self.country_embedding(country_id)
        asn_emb = self.asn_embedding(asn_id)
        days_since_reg_output = torch.relu(self.ip_numeric_fc(days_since_reg))

        # 모든 피처를 결합
        combined_features = torch.cat((bert_output, country_emb, asn_emb, days_since_reg_output), dim=1)

        # 분류
        is_phishing_logits = self.fc1_is_phishing(self.dropout(combined_features))
        phishing_type_logits = self.fc2_phishing_type(self.dropout(combined_features))

        return is_phishing_logits, phishing_type_logits


# 4. 학습 및 평가 함수 정의
def train_model(model, data_loader, optimizer, loss_fn, device, n_epochs):
    model = model.train()
    total_loss = 0
    
    for epoch in range(n_epochs):
        for d in data_loader:
            input_ids = d["input_ids"].to(device)
            attention_mask = d["attention_mask"].to(device)
            days_since_reg = d["days_since_reg"].to(device)
            country_id = d["country_id"].to(device)
            asn_id = d["asn_id"].to(device)

            is_phishing_label = d["is_phishing_label"].to(device)
            phishing_type_label = d["phishing_type_label"].to(device)

            is_phishing_logits, phishing_type_logits = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                days_since_reg=days_since_reg,
                country_id=country_id,
                asn_id=asn_id
            )

            loss1 = loss_fn(is_phishing_logits, is_phishing_label)
            loss2 = loss_fn(phishing_type_logits, phishing_type_label)
            loss = loss1 + loss2

            loss.backward()
            optimizer.step()
            optimizer.zero_grad()
            total_loss += loss.item()

    print(f"Training Loss: {total_loss / len(data_loader)}")


def eval_model(model, data_loader, device):
    model = model.eval()
    
    is_phishing_predictions = []
    is_phishing_labels = []
    phishing_type_predictions = []
    phishing_type_labels = []

    with torch.no_grad():
        for d in data_loader:
            input_ids = d["input_ids"].to(device)
            attention_mask = d["attention_mask"].to(device)
            days_since_reg = d["days_since_reg"].to(device)
            country_id = d["country_id"].to(device)
            asn_id = d["asn_id"].to(device)

            is_phishing_label = d["is_phishing_label"].to(device)
            phishing_type_label = d["phishing_type_label"].to(device)
            
            is_phishing_logits, phishing_type_logits = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                days_since_reg=days_since_reg,
                country_id=country_id,
                asn_id=asn_id
            )

            _, is_phishing_preds = torch.max(is_phishing_logits, dim=1)
            _, phishing_type_preds = torch.max(phishing_type_logits, dim=1)

            is_phishing_predictions.extend(is_phishing_preds.cpu().numpy())
            is_phishing_labels.extend(is_phishing_label.cpu().numpy())
            phishing_type_predictions.extend(phishing_type_preds.cpu().numpy())
            phishing_type_labels.extend(phishing_type_label.cpu().numpy())

    # 결과 보고서
    print("\n--- 피싱 여부 분류 결과 ---")
    print(classification_report(is_phishing_labels, is_phishing_predictions, target_names=['normal', 'phishing']))
    
    print("\n--- 피싱 유형 분류 결과 ---")
    phishing_type_names = list(label_map.keys())
    print(classification_report(phishing_type_labels, phishing_type_predictions, target_names=phishing_type_names))


# 5. 메인 함수 실행
if __name__ == "__main__":
    # 하이퍼파라미터 설정
    BERT_MODEL_NAME = 'bert-base-uncased'
    MAX_LEN = 128
    BATCH_SIZE = 16
    N_EPOCHS = 10
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # 데이터 분할
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)
    
    tokenizer = BertTokenizer.from_pretrained(BERT_MODEL_NAME)

    # 데이터셋 및 데이터로더 생성
    train_dataset = PhishingDataset(
        df=train_df,
        tokenizer=tokenizer,
        max_len=MAX_LEN,
        label_maps=label_maps
    )
    test_dataset = PhishingDataset(
        df=test_df,
        tokenizer=tokenizer,
        max_len=MAX_LEN,
        label_maps=label_maps
    )
    
    train_data_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_data_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)
    
    # 모델, 손실 함수, 옵티마이저 초기화
    n_is_phishing_classes = 2
    n_phishing_type_classes = len(label_map)
    num_countries = len(label_maps['country'])
    num_asns = df['asn_id'].max() + 1
    
    model = PhishingClassifier(
        n_is_phishing_classes=n_is_phishing_classes,
        n_phishing_type_classes=n_phishing_type_classes,
        bert_model_name=BERT_MODEL_NAME,
        num_countries=num_countries,
        num_asns=num_asns
    )
    model = model.to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=2e-5)
    loss_fn = nn.CrossEntropyLoss().to(device)

    # 모델 학습
    print("모델 학습 시작...")
    train_model(model, train_data_loader, optimizer, loss_fn, device, N_EPOCHS)
    print("모델 학습 완료!")

    # 모델 평가
    print("모델 평가 시작...")
    eval_model(model, test_data_loader, device)
    print("모델 평가 완료!")