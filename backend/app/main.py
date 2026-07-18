from pathlib import Path

from dotenv import load_dotenv

# Local development only: real deployment credentials should come from the host environment.
# `override=False` ensures an explicitly configured environment variable always wins.
# This runs before the mission service is created, so the AI client sees local settings.
load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware

from app.models import Explanation, Finding, Mission, MissionReport, PatchProposal, StartMissionRequest, StartMissionResponse, VerificationResult
from app.repository_service import RepositoryError
from app.services import MissionNotFoundError, WorkflowError, mission_service

app = FastAPI(title="Kavach AI API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "kavach-security-mission-control"}


@app.post("/api/v1/mission/start", response_model=StartMissionResponse, status_code=202)
def start_mission(payload: StartMissionRequest, background_tasks: BackgroundTasks) -> StartMissionResponse:
    try:
        mission = mission_service.create(payload.repository_url)
    except RepositoryError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    background_tasks.add_task(mission_service.execute, mission.id)
    return StartMissionResponse(mission_id=mission.id)


@app.get("/api/v1/mission/{mission_id}", response_model=Mission)
def get_mission(mission_id: str) -> Mission:
    mission = mission_service.get(mission_id)
    if mission is None:
        raise HTTPException(status_code=404, detail="Mission not found")
    return mission


@app.get("/api/v1/findings/{mission_id}", response_model=list[Finding])
def get_findings(mission_id: str) -> list[Finding]:
    try:
        return mission_service.get_findings(mission_id)
    except MissionNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/api/v1/mission/{mission_id}/findings/{finding_id}/analyze", response_model=Explanation)
def analyze_finding(mission_id: str, finding_id: str) -> Explanation:
    try:
        return mission_service.analyze(mission_id, finding_id)
    except MissionNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except WorkflowError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.post("/api/v1/mission/{mission_id}/findings/{finding_id}/patch", response_model=PatchProposal)
def propose_patch(mission_id: str, finding_id: str) -> PatchProposal:
    try:
        return mission_service.propose_patch(mission_id, finding_id)
    except MissionNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except WorkflowError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.post("/api/v1/mission/{mission_id}/patches/{patch_id}/verify", response_model=VerificationResult)
def verify_patch(mission_id: str, patch_id: str) -> VerificationResult:
    try:
        return mission_service.verify_patch(mission_id, patch_id)
    except MissionNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except WorkflowError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.get("/api/v1/mission/{mission_id}/report", response_model=MissionReport)
def get_report(mission_id: str) -> MissionReport:
    try:
        return mission_service.report(mission_id)
    except MissionNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.delete("/api/v1/mission/{mission_id}", status_code=204)
def cleanup_mission(mission_id: str) -> Response:
    if mission_service.get(mission_id) is None:
        raise HTTPException(status_code=404, detail="Mission not found")
    mission_service.cleanup(mission_id)
    return Response(status_code=204)


@app.post("/api/v1/explain/{finding_id}", response_model=Explanation, deprecated=True)
def explain_finding(finding_id: str) -> Explanation:
    """Compatibility route. New clients must provide the mission ID in the URL."""
    explanation = mission_service.explain(finding_id)
    if explanation is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return explanation
