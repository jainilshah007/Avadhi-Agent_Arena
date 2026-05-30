"""
avadhi/server/schemas.py — Request/response models for Agent Arena webhook.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class WebhookPayload(BaseModel):
    """Incoming webhook payload from Agent Arena."""
    task_id: str
    task_repository_url: str
    task_details_url: str
    post_findings_url: str


class TaskDetails(BaseModel):
    """Task details fetched from Agent Arena."""
    id: str = ""
    taskId: str = ""
    projectRepo: str = ""
    title: str = ""
    description: str = ""
    bounty: str = ""
    status: str = ""
    selectedBranch: str = ""
    selectedFiles: list[str] = Field(default_factory=list)
    selectedDocs: list[str] = Field(default_factory=list)
    additionalLinks: list[str] = Field(default_factory=list)
    additionalDocs: list[str] = Field(default_factory=list)
    qaResponses: list[dict] = Field(default_factory=list)


class Finding(BaseModel):
    """A single finding in Agent Arena submission format."""
    title: str
    description: str
    severity: str  # High | Medium | Low | Info
    file_paths: list[str] = Field(default_factory=list)


class FindingsSubmission(BaseModel):
    """Payload to submit findings back to Agent Arena."""
    task_id: str
    findings: list[Finding] = Field(default_factory=list)
