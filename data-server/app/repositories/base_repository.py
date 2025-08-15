"""
Base repository class for common database operations
"""

from typing import List, Optional, Dict, Any, Type, TypeVar
from sqlalchemy.exc import SQLAlchemyError
from flask_sqlalchemy import Model
from app import db
from app.core.exceptions import DatabaseError

T = TypeVar('T', bound=Model)

class BaseRepository:
    """Base repository with common database operations."""
    
    def __init__(self, model_class: Type[T]):
        self.model_class = model_class
    
    def find_by_id(self, id: Any) -> Optional[T]:
        """Find model instance by ID."""
        try:
            return self.model_class.query.get(id)
        except SQLAlchemyError as e:
            raise DatabaseError(f"Error finding {self.model_class.__name__} by ID: {str(e)}")
    
    def find_all(self, limit: int = None, offset: int = None) -> List[T]:
        """Find all model instances with optional pagination."""
        try:
            query = self.model_class.query
            if offset is not None:
                query = query.offset(offset)
            if limit is not None:
                query = query.limit(limit)
            return query.all()
        except SQLAlchemyError as e:
            raise DatabaseError(f"Error finding all {self.model_class.__name__}: {str(e)}")
    
    def find_by_criteria(self, **criteria) -> List[T]:
        """Find model instances by criteria."""
        try:
            return self.model_class.query.filter_by(**criteria).all()
        except SQLAlchemyError as e:
            raise DatabaseError(f"Error finding {self.model_class.__name__} by criteria: {str(e)}")
    
    def create(self, **kwargs) -> T:
        """Create new model instance."""
        try:
            instance = self.model_class(**kwargs)
            db.session.add(instance)
            db.session.commit()
            return instance
        except SQLAlchemyError as e:
            db.session.rollback()
            raise DatabaseError(f"Error creating {self.model_class.__name__}: {str(e)}")
    
    def update(self, instance: T, **kwargs) -> T:
        """Update model instance."""
        try:
            for key, value in kwargs.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)
            db.session.commit()
            return instance
        except SQLAlchemyError as e:
            db.session.rollback()
            raise DatabaseError(f"Error updating {self.model_class.__name__}: {str(e)}")
    
    def delete(self, instance: T) -> bool:
        """Delete model instance."""
        try:
            db.session.delete(instance)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            raise DatabaseError(f"Error deleting {self.model_class.__name__}: {str(e)}")
    
    def count(self, **criteria) -> int:
        """Count model instances by criteria."""
        try:
            query = self.model_class.query
            if criteria:
                query = query.filter_by(**criteria)
            return query.count()
        except SQLAlchemyError as e:
            raise DatabaseError(f"Error counting {self.model_class.__name__}: {str(e)}")
    
    def exists(self, **criteria) -> bool:
        """Check if model instance exists by criteria."""
        try:
            return self.model_class.query.filter_by(**criteria).first() is not None
        except SQLAlchemyError as e:
            raise DatabaseError(f"Error checking existence of {self.model_class.__name__}: {str(e)}")