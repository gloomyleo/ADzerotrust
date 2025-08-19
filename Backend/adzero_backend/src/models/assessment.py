from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class Assessment(db.Model):
    """Main assessment record"""
    __tablename__ = 'assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(100), nullable=False)
    assessment_type = db.Column(db.String(50), nullable=False)  # Quick, Standard, Comprehensive
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Assessment configuration
    config_json = db.Column(db.Text)  # JSON configuration
    
    # Results summary
    total_identities = db.Column(db.Integer, default=0)
    high_risk_items = db.Column(db.Integer, default=0)
    zero_trust_score = db.Column(db.Float, default=0.0)
    maturity_level = db.Column(db.String(50))  # Traditional, Initial, Intermediate, Advanced
    
    # Relationships
    modules = db.relationship('AssessmentModule', backref='assessment', lazy=True, cascade='all, delete-orphan')
    recommendations = db.relationship('Recommendation', backref='assessment', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'domain': self.domain,
            'assessment_type': self.assessment_type,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'config': json.loads(self.config_json) if self.config_json else {},
            'total_identities': self.total_identities,
            'high_risk_items': self.high_risk_items,
            'zero_trust_score': self.zero_trust_score,
            'maturity_level': self.maturity_level,
            'modules_count': len(self.modules),
            'recommendations_count': len(self.recommendations)
        }

class AssessmentModule(db.Model):
    """Individual assessment module results"""
    __tablename__ = 'assessment_modules'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    module_name = db.Column(db.String(100), nullable=False)  # ADInfoGatherer, IdentityAnalyzer, etc.
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, failed
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Results
    results_json = db.Column(db.Text)  # JSON results from PowerShell module
    error_message = db.Column(db.Text)
    
    # Summary metrics
    items_analyzed = db.Column(db.Integer, default=0)
    high_risk_count = db.Column(db.Integer, default=0)
    medium_risk_count = db.Column(db.Integer, default=0)
    low_risk_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'assessment_id': self.assessment_id,
            'module_name': self.module_name,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'results': json.loads(self.results_json) if self.results_json else {},
            'error_message': self.error_message,
            'items_analyzed': self.items_analyzed,
            'high_risk_count': self.high_risk_count,
            'medium_risk_count': self.medium_risk_count,
            'low_risk_count': self.low_risk_count
        }

class Recommendation(db.Model):
    """Security recommendations from assessments"""
    __tablename__ = 'recommendations'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.String(50), nullable=False)  # Critical, High, Medium, Low
    issue = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    zero_trust_principle = db.Column(db.String(100))
    
    # Implementation details
    implementation_steps = db.Column(db.Text)  # JSON array
    affected_count = db.Column(db.Integer, default=0)
    estimated_effort = db.Column(db.String(50))  # Low, Medium, High
    
    # Status tracking
    status = db.Column(db.String(50), default='open')  # open, in_progress, completed, dismissed
    assigned_to = db.Column(db.String(100))
    due_date = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'assessment_id': self.assessment_id,
            'category': self.category,
            'priority': self.priority,
            'issue': self.issue,
            'recommendation': self.recommendation,
            'zero_trust_principle': self.zero_trust_principle,
            'implementation_steps': json.loads(self.implementation_steps) if self.implementation_steps else [],
            'affected_count': self.affected_count,
            'estimated_effort': self.estimated_effort,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'notes': self.notes
        }

class IdentityRisk(db.Model):
    """Identity-specific risk tracking"""
    __tablename__ = 'identity_risks'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    identity_name = db.Column(db.String(200), nullable=False)
    identity_type = db.Column(db.String(50), nullable=False)  # Human, NonHuman, Service
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(50))  # Low, Medium, High
    
    # Risk factors
    risk_factors = db.Column(db.Text)  # JSON array
    is_privileged = db.Column(db.Boolean, default=False)
    is_stale = db.Column(db.Boolean, default=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    
    # Additional details
    last_logon = db.Column(db.DateTime)
    password_last_set = db.Column(db.DateTime)
    groups_json = db.Column(db.Text)  # JSON array of group memberships
    
    def to_dict(self):
        return {
            'id': self.id,
            'assessment_id': self.assessment_id,
            'identity_name': self.identity_name,
            'identity_type': self.identity_type,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'risk_factors': json.loads(self.risk_factors) if self.risk_factors else [],
            'is_privileged': self.is_privileged,
            'is_stale': self.is_stale,
            'mfa_enabled': self.mfa_enabled,
            'last_logon': self.last_logon.isoformat() if self.last_logon else None,
            'password_last_set': self.password_last_set.isoformat() if self.password_last_set else None,
            'groups': json.loads(self.groups_json) if self.groups_json else []
        }

class PermissionRisk(db.Model):
    """Permission-specific risk tracking"""
    __tablename__ = 'permission_risks'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    resource_path = db.Column(db.String(500), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # FileSystem, Share, Registry
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(50))  # Low, Medium, High
    
    # Risk factors
    risk_factors = db.Column(db.Text)  # JSON array
    has_anonymous_access = db.Column(db.Boolean, default=False)
    has_broad_access = db.Column(db.Boolean, default=False)
    has_full_control = db.Column(db.Boolean, default=False)
    
    # Permission details
    owner = db.Column(db.String(200))
    permissions_json = db.Column(db.Text)  # JSON array of permissions
    
    def to_dict(self):
        return {
            'id': self.id,
            'assessment_id': self.assessment_id,
            'resource_path': self.resource_path,
            'resource_type': self.resource_type,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'risk_factors': json.loads(self.risk_factors) if self.risk_factors else [],
            'has_anonymous_access': self.has_anonymous_access,
            'has_broad_access': self.has_broad_access,
            'has_full_control': self.has_full_control,
            'owner': self.owner,
            'permissions': json.loads(self.permissions_json) if self.permissions_json else []
        }

class ZeroTrustRoadmap(db.Model):
    """Zero Trust implementation roadmap"""
    __tablename__ = 'zero_trust_roadmaps'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    
    # Timeline
    timeline_months = db.Column(db.Integer, default=12)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Maturity progression
    current_maturity = db.Column(db.String(50))
    target_maturity = db.Column(db.String(50))
    
    # Roadmap content
    phases_json = db.Column(db.Text)  # JSON array of phases
    milestones_json = db.Column(db.Text)  # JSON array of milestones
    resources_json = db.Column(db.Text)  # JSON object of resource requirements
    metrics_json = db.Column(db.Text)  # JSON array of success metrics
    
    def to_dict(self):
        return {
            'id': self.id,
            'assessment_id': self.assessment_id,
            'name': self.name,
            'description': self.description,
            'timeline_months': self.timeline_months,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'current_maturity': self.current_maturity,
            'target_maturity': self.target_maturity,
            'phases': json.loads(self.phases_json) if self.phases_json else [],
            'milestones': json.loads(self.milestones_json) if self.milestones_json else [],
            'resources': json.loads(self.resources_json) if self.resources_json else {},
            'metrics': json.loads(self.metrics_json) if self.metrics_json else []
        }

