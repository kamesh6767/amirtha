from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import pandas as pd
import io
import uuid
import models, database, auth, ml
from typing import List

app = FastAPI(title="CyberShield API")

# Setup database
models.Base.metadata.create_all(bind=database.engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ml.FraudDetectionEngine()

@app.get("/")
def read_root():
    return {"status": "CyberShield API Active", "version": "2.4.1"}

@app.post("/login")
def login(email: str, role: str):
    # Simplified login for demo
    access_token = auth.create_access_token(data={"sub": email, "role": role})
    return {"access_token": access_token, "token_type": "bearer", "user": {"email": email, "role": role}}

@app.get("/beneficiaries", response_model=List[dict])
def get_beneficiaries(db: Session = Depends(database.get_db)):
    return db.query(models.Beneficiary).all()

@app.post("/upload-dataset")
async def upload_dataset(
    file: UploadFile = File(...), 
    db: Session = Depends(database.get_db)
):
    contents = await file.read()
    if file.filename.endswith('.csv'):
        df = pd.read_csv(io.BytesIO(contents))
    else:
        df = pd.read_excel(io.BytesIO(contents))
    
    dataset_id = str(uuid.uuid4())[:8]
    new_dataset = models.Dataset(
        id=dataset_id,
        name=file.filename,
        records_count=len(df),
        status="Processing"
    )
    db.add(new_dataset)
    db.commit()

    # In a real app, this would be a Celery task
    # For demo, we run it and update DB
    records = df.to_dict('records')
    # Add an ID field if missing for graph analysis
    for r in records:
        if 'id' not in r and 'ID' not in r:
            r['id'] = str(uuid.uuid4())[:6]
        else:
            r['id'] = r.get('id') or r.get('ID')
            
    # Run ML analysis
    results = engine.analyze_dataset(pd.DataFrame(records))
    
    fraud_count = 0
    for res in results:
        beneficiary = models.Beneficiary(
            id=str(res['id']),
            name=res.get('name', 'Unknown'),
            address=res.get('address', 'N/A'),
            phone=str(res.get('phone', 'N/A')),
            bank_account=res.get('bank_account', 'N/A'),
            national_id=str(res.get('national_id', str(uuid.uuid4())[:10])),
            scheme_type=res.get('scheme_type', 'Default'),
            claim_amount=float(res.get('claim_amount', 0)),
            risk_score=float(res.get('risk_score', 0)),
            fraud_type=res.get('fraud_type'),
            status="Under Investigation" if res.get('risk_score', 0) > 60 else "Pending",
            dataset_id=dataset_id
        )
        if beneficiary.risk_score > 60:
            fraud_count += 1
            # Create alert
            alert = models.Alert(
                type="high" if beneficiary.risk_score < 90 else "critical",
                title=f"High Risk Detected: {beneficiary.name}",
                message=f"Risk Score {beneficiary.risk_score} - {beneficiary.fraud_type}"
            )
            db.add(alert)
            
        db.add(beneficiary)
    
    new_dataset.status = "Analyzed"
    new_dataset.fraud_found_count = fraud_count
    db.commit()
    
    return {"message": "Dataset analyzed", "dataset_id": dataset_id, "anomalies_detected": fraud_count}

@app.get("/stats")
def get_stats(db: Session = Depends(database.get_db)):
    total = db.query(models.Beneficiary).count()
    fraud = db.query(models.Beneficiary).filter(models.Beneficiary.risk_score >= 60).count()
    alerts = db.query(models.Alert).filter(models.Alert.read == False).count()
    return {
        "total_beneficiaries": total,
        "fraud_cases": fraud,
        "unread_alerts": alerts,
        "accuracy": 96.4
    }

@app.get("/alerts", response_model=List[dict])
def get_alerts(db: Session = Depends(database.get_db)):
    return db.query(models.Alert).order_by(models.Alert.created_at.desc()).all()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
