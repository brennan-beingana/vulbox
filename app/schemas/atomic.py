from typing import List, Optional

from pydantic import BaseModel


class AtomicTest(BaseModel):
    technique_id: str
    technique_name: str
    test_name: str
    status: str
    timestamp: str
    message: Optional[str] = None


class AtomicIngestionPayload(BaseModel):
    tests: List[AtomicTest]


class AtomicResponse(BaseModel):
    message: str
    tests_count: int
