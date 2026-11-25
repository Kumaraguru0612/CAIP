"""
CAIP Notification & Alerting Engine — Phase 8.3
===============================================
Manages in-app SOC notification center and alert broadcasts for:
  • 🔴 CRITICAL_INCIDENT: Incident created with CRITICAL severity / P1
  • 🟠 HIGH_RISK_CAMPAIGN: Campaign risk score escalated >= 80
  • 👤 CASE_ASSIGNMENT: Incident assigned / auto-assigned to analyst
  • ⏰ SLA_BREACH: Case exceeding or nearing SLA response limits
  • ✅ CONTAINMENT: Host containment / remediation action completed
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.database.models import Notification


class NotificationEngine:
    """
    Central hub for creating, querying, and managing in-app SOC alerts.
    """

    def create_notification(
        self,
        type: str,
        title: str,
        message: str,
        severity: str = "HIGH",
        link_type: Optional[str] = None,
        link_id: Optional[str] = None,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Create and commit a new notification."""
        if not db:
            return {}

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        notif_id = f"NOTIF-{uuid.uuid4().hex[:6].upper()}"

        notif = Notification(
            notification_id=notif_id,
            type=type,
            title=title,
            message=message,
            severity=severity.upper(),
            link_type=link_type,
            link_id=link_id,
            is_read=False,
            created_at=now
        )
        db.add(notif)
        db.commit()
        db.refresh(notif)

        return self._to_dict(notif)

    def list_notifications(
        self,
        unread_only: bool = False,
        limit: int = 50,
        db: Optional[Session] = None
    ) -> List[Dict[str, Any]]:
        """List notifications ordered by recency."""
        if not db:
            return []

        query = db.query(Notification)
        if unread_only:
            query = query.filter(Notification.is_read == False)

        notifs = query.order_by(Notification.created_at.desc()).limit(limit).all()
        return [self._to_dict(n) for n in notifs]

    def get_unread_count(self, db: Session) -> int:
        """Get total number of unread notifications."""
        return db.query(Notification).filter(Notification.is_read == False).count()

    def mark_as_read(self, notification_id: str, db: Session) -> bool:
        """Mark a single notification as read."""
        notif = db.query(Notification).filter(Notification.notification_id == notification_id).first()
        if notif:
            notif.is_read = True
            db.commit()
            return True
        return False

    def mark_all_as_read(self, db: Session) -> int:
        """Mark all notifications as read."""
        unread = db.query(Notification).filter(Notification.is_read == False).all()
        count = len(unread)
        for n in unread:
            n.is_read = True
        db.commit()
        return count

    def _to_dict(self, n: Notification) -> Dict[str, Any]:
        return {
            "notification_id": n.notification_id,
            "type": n.type,
            "title": n.title,
            "message": n.message,
            "severity": n.severity,
            "link_type": n.link_type,
            "link_id": n.link_id,
            "is_read": n.is_read,
            "created_at": n.created_at.isoformat() if n.created_at else "",
            "time_display": n.created_at.strftime("%I:%M %p") if n.created_at else ""
        }
