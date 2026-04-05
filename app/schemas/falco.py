from typing import List, Optional

from pydantic import BaseModel, Field


class FalcoContainer(BaseModel):
    name: str
    id: str


class FalcoProcess(BaseModel):
    name: str
    args: Optional[str] = None


class FalcoFile(BaseModel):
    name: str


class FalcoAlert(BaseModel):
    priority: str
    rule: str
    time: str
    output: str
    container: FalcoContainer
    process: Optional[FalcoProcess] = None
    file: Optional[FalcoFile] = None


class FalcoIngestionPayload(BaseModel):
    alerts: List[FalcoAlert]


class FalcoResponse(BaseModel):
    message: str
    alerts_count: int
