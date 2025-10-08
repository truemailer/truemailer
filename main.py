from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow frontend (Replit, Render, etc.) access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root route (for testing Render)
@app.get("/")
async def home():
    return {"message": "✅ Server is running properly on Render & Replit"}

# POST route for email verification testing
@app.post("/verify")
async def verify_post(email: str = Form(...)):
    # Basic example logic
    if "@" not in email:
        return JSONResponse(content={"status": "❌ invalid email"}, status_code=400)
    return JSONResponse(content={"status": "✅ email verified", "email": email})
