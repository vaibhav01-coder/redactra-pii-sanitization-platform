from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from app.models import AuditLog


def export_audit_pdf(logs: list[AuditLog], destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(destination), pagesize=A4)
    width, height = A4
    y = height - 40

    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "CASE FILED - Chain of Custody")
    y -= 30
    c.setFont("Helvetica", 9)

    for log in logs:
        line = (
            f"{log.created_at.isoformat()} | {log.event_type.value} | user={log.user_id} "
            f"| file={log.file_id} | hash={log.entry_hash[:16]}..."
        )
        c.drawString(40, y, line[:130])
        y -= 14
        if y < 60:
            c.showPage()
            c.setFont("Helvetica", 9)
            y = height - 40

    c.save()
    return destination
