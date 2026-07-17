from __future__ import annotations

import csv
import re
from typing import List

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from email_verifier import EmailVerificationEngine


app = FastAPI(
    title="Email Verification API",
    version="1.0.0",
    description="Production-ready email verification service with layered validation and social graph checks.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:3000",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.email_engine = EmailVerificationEngine(
    sender_email="sender@example.com",
    helo_domain="example.com",
    timeout=3.0,
    max_retries=1,
    request_timeout=2.0,
)


class SingleEmailRequest(BaseModel):
    email: EmailStr = Field(..., description="A single email address to verify")


class VerificationResult(BaseModel):
    status: str
    reason: str
    verification_tier: str
    context_logs: List[dict]
    social_profile_metadata: dict


class BulkVerificationResponse(BaseModel):
    results: List[VerificationResult]
    processed_count: int
    unique_count: int


class ErrorDetail(BaseModel):
    detail: str


def get_engine(request: Request) -> EmailVerificationEngine:
    return request.app.state.email_engine


EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")


async def _extract_emails_from_upload(file: UploadFile) -> List[str]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="A file with a valid filename is required")

    extension = file.filename.lower().rsplit(".", 1)[-1] if "." in file.filename else ""
    if extension not in {"csv", "txt"}:
        raise HTTPException(status_code=400, detail="Only .csv and .txt files are supported")

    try:
        contents = await file.read()
        text = contents.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Unable to decode file as UTF-8: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to read uploaded file: {exc}") from exc

    if not text.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        if extension == "csv":
            parsed_rows = list(csv.reader(text.splitlines()))
            candidates = [field for row in parsed_rows for field in row if field]
        else:
            candidates = text.splitlines()

        emails = []
        for candidate in candidates:
            emails.extend(EMAIL_PATTERN.findall(candidate))

        unique_emails = []
        seen = set()
        for email in emails:
            normalized = email.strip().lower()
            if normalized not in seen:
                seen.add(normalized)
                unique_emails.append(normalized)
        return unique_emails
    except csv.Error as exc:
        raise HTTPException(status_code=400, detail=f"The CSV file is malformed: {exc}") from exc


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


@app.post("/api/verify-single", response_model=VerificationResult, tags=["verification"])
@app.get("/api/verify-single", response_model=VerificationResult, tags=["verification"])
def verify_single_email(
    email: str | None = None,
    request_body: SingleEmailRequest | None = None,
    engine: EmailVerificationEngine = Depends(get_engine),
):
    if request_body is not None:
        target_email = request_body.email
    elif email is not None:
        target_email = email
    else:
        raise HTTPException(status_code=422, detail="An email address is required")

    result = engine.verify_email(str(target_email).strip())
    return VerificationResult(**result)


@app.post("/api/verify-bulk", response_model=BulkVerificationResponse, tags=["verification"])
async def verify_bulk_emails(
    file: UploadFile = File(...),
    engine: EmailVerificationEngine = Depends(get_engine),
):
    try:
        emails = await _extract_emails_from_upload(file)
    except HTTPException:
        raise

    if not emails:
        raise HTTPException(status_code=400, detail="No valid email addresses were found in the uploaded file")

    results = engine.verify_batch(emails, max_workers=min(8, len(emails)))
    return BulkVerificationResponse(
        results=[VerificationResult(**result) for result in results],
        processed_count=len(results),
        unique_count=len(emails),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
