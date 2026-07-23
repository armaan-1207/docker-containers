from typing import Literal
from pydantic import BaseModel, HttpUrl

from schemas.stage2 import Stage2Response


class FullScanRequest(BaseModel):
    url: HttpUrl


class FullScanResponse(Stage2Response):
    captured_by: Literal["extension", "server"] = "server"
