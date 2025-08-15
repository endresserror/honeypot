"""
Repository for AttackLog model operations
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import desc, func
from app.models.attack_log import AttackLog
from app.repositories.base_repository import BaseRepository
from app.core.exceptions import DatabaseError
from app import db

class AttackLogRepository(BaseRepository):
    """Repository for AttackLog operations."""
    
    def __init__(self):
        super().__init__(AttackLog)
    
    def find_unprocessed(self, limit: int = None) -> List[AttackLog]:
        """Find unprocessed attack logs."""
        try:
            query = AttackLog.query.filter_by(processed=False)
            if limit:
                query = query.limit(limit)
            return query.all()
        except Exception as e:
            raise DatabaseError(f"Error finding unprocessed logs: {str(e)}")
    
    def find_by_ip(self, source_ip: str, limit: int = None) -> List[AttackLog]:
        """Find attack logs by source IP."""
        try:
            query = AttackLog.query.filter_by(source_ip=source_ip)
            query = query.order_by(desc(AttackLog.timestamp))
            if limit:
                query = query.limit(limit)
            return query.all()
        except Exception as e:
            raise DatabaseError(f"Error finding logs by IP: {str(e)}")
    
    def find_by_attack_type(self, attack_type: str, limit: int = None) -> List[AttackLog]:
        """Find attack logs by attack type."""
        try:
            query = AttackLog.query.filter_by(attack_type=attack_type)
            query = query.order_by(desc(AttackLog.timestamp))
            if limit:
                query = query.limit(limit)
            return query.all()
        except Exception as e:
            raise DatabaseError(f"Error finding logs by attack type: {str(e)}")
    
    def find_by_time_range(self, start_time: datetime, end_time: datetime) -> List[AttackLog]:
        """Find attack logs within time range."""
        try:
            return AttackLog.query.filter(
                AttackLog.timestamp >= start_time,
                AttackLog.timestamp <= end_time
            ).order_by(desc(AttackLog.timestamp)).all()
        except Exception as e:
            raise DatabaseError(f"Error finding logs by time range: {str(e)}")
    
    def get_attack_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get attack statistics for the last N hours."""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Total attacks
            total_attacks = AttackLog.query.filter(
                AttackLog.timestamp >= cutoff_time
            ).count()
            
            # Attack types distribution
            attack_types = db.session.query(
                AttackLog.attack_type,
                func.count(AttackLog.id).label('count')
            ).filter(
                AttackLog.timestamp >= cutoff_time
            ).group_by(AttackLog.attack_type).all()
            
            # Top attacking IPs
            top_ips = db.session.query(
                AttackLog.source_ip,
                func.count(AttackLog.id).label('count')
            ).filter(
                AttackLog.timestamp >= cutoff_time
            ).group_by(AttackLog.source_ip).order_by(
                func.count(AttackLog.id).desc()
            ).limit(10).all()
            
            return {
                'total_attacks': total_attacks,
                'attack_types': [{'type': t[0], 'count': t[1]} for t in attack_types],
                'top_ips': [{'ip': ip[0], 'count': ip[1]} for ip in top_ips],
                'time_period_hours': hours
            }
        except Exception as e:
            raise DatabaseError(f"Error getting attack statistics: {str(e)}")
    
    def mark_processed(self, attack_log_id: int) -> bool:
        """Mark attack log as processed."""
        try:
            log = self.find_by_id(attack_log_id)
            if log:
                log.processed = True
                db.session.commit()
                return True
            return False
        except Exception as e:
            db.session.rollback()
            raise DatabaseError(f"Error marking log as processed: {str(e)}")
    
    def bulk_mark_processed(self, log_ids: List[int]) -> int:
        """Mark multiple attack logs as processed."""
        try:
            updated_count = AttackLog.query.filter(
                AttackLog.id.in_(log_ids)
            ).update({'processed': True}, synchronize_session=False)
            
            db.session.commit()
            return updated_count
        except Exception as e:
            db.session.rollback()
            raise DatabaseError(f"Error bulk marking logs as processed: {str(e)}")