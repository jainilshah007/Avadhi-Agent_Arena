"""
avadhi/server/schemas.py — Request/response models for Agent Arena webhook.
"""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class WebhookPayload(BaseModel):
    """Incoming webhook payload from Agent Arena."""
    task_id: str = ""
    task_repository_url: str = ""
    task_details_url: str = ""
    post_findings_url: str = ""


class TaskDetails(BaseModel):
    """Task details fetched from Agent Arena."""
    id: Any = ""
    taskId: Any = ""
    projectRepo: Any = ""
    title: Any = ""
    description: Any = ""
    bounty: Any = ""
    status: Any = ""
    selectedBranch: Any = ""
    selectedFiles: Any = None
    selectedDocs: Any = None
    additionalLinks: Any = None
    additionalDocs: Any = None
    qaResponses: Any = None


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
