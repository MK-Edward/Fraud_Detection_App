from pydantic import BaseModel, ConfigDict, Field

class TransactionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    distance_from_home: float = Field(ge=0)
    distance_from_last_transaction: float = Field(ge=0)
    ratio_to_median_purchase_price: float = Field(ge=0)
    
    repeat_retailer: int = Field(ge=0, le=1)
    used_chip: int = Field(ge=0, le=1)
    used_pin_number: int = Field(ge=0, le=1)
    online_order: int = Field(ge=0, le=1)

class PredictionResponse(BaseModel):
    fraud_prediction: int
    fraud_probability: float | None = None
    risk_level: str
    decision: str

# Keep your existing TransactionRequest and PredictionResponse definitions above this!

class UserAuth(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
