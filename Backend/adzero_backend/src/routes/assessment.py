from flask import Blueprint, jsonify, request
from src.models.assessment import Assessment, AssessmentModule, Recommendation, IdentityRisk, PermissionRisk, db
from datetime import datetime
import json

assessment_bp = Blueprint('assessment', __name__)

@assessment_bp.route('/assessments', methods=['GET'])
def get_assessments():
    """Get all assessments with optional filtering"""
    try:
        # Query parameters
        status = request.args.get('status')
        domain = request.args.get('domain')
        assessment_type = request.args.get('type')
        limit = request.args.get('limit', type=int)
        
        # Build query
        query = Assessment.query
        
        if status:
            query = query.filter(Assessment.status == status)
        if domain:
            query = query.filter(Assessment.domain.ilike(f'%{domain}%'))
        if assessment_type:
            query = query.filter(Assessment.assessment_type == assessment_type)
        
        # Order by creation date (newest first)
        query = query.order_by(Assessment.created_at.desc())
        
        if limit:
            query = query.limit(limit)
        
        assessments = query.all()
        
        return jsonify({
            'success': True,
            'data': [assessment.to_dict() for assessment in assessments],
            'count': len(assessments)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments', methods=['POST'])
def create_assessment():
    """Create a new assessment"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['name', 'domain', 'assessment_type']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Validate assessment type
        valid_types = ['Quick', 'Standard', 'Comprehensive']
        if data['assessment_type'] not in valid_types:
            return jsonify({
                'success': False,
                'error': f'Invalid assessment type. Must be one of: {valid_types}'
            }), 400
        
        # Create assessment
        assessment = Assessment(
            name=data['name'],
            domain=data['domain'],
            assessment_type=data['assessment_type'],
            config_json=json.dumps(data.get('config', {}))
        )
        
        db.session.add(assessment)
        db.session.commit()
        
        # Create assessment modules based on type
        modules_config = {
            'Quick': ['ADInfoGatherer', 'IdentityAnalyzer'],
            'Standard': ['ADInfoGatherer', 'IdentityAnalyzer', 'PermissionAssessor', 'SecurityAuditor'],
            'Comprehensive': ['ADInfoGatherer', 'IdentityAnalyzer', 'PermissionAssessor', 'SecurityAuditor']
        }
        
        modules = modules_config.get(data['assessment_type'], modules_config['Standard'])
        
        for module_name in modules:
            module = AssessmentModule(
                assessment_id=assessment.id,
                module_name=module_name
            )
            db.session.add(module)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': assessment.to_dict(),
            'message': 'Assessment created successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments/<int:assessment_id>', methods=['GET'])
def get_assessment(assessment_id):
    """Get a specific assessment with detailed information"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Get detailed information
        result = assessment.to_dict()
        
        # Add modules information
        result['modules'] = [module.to_dict() for module in assessment.modules]
        
        # Add recommendations
        result['recommendations'] = [rec.to_dict() for rec in assessment.recommendations]
        
        # Add risk summary
        identity_risks = IdentityRisk.query.filter_by(assessment_id=assessment_id).all()
        permission_risks = PermissionRisk.query.filter_by(assessment_id=assessment_id).all()
        
        result['risk_summary'] = {
            'identity_risks': {
                'total': len(identity_risks),
                'high': len([r for r in identity_risks if r.risk_level == 'High']),
                'medium': len([r for r in identity_risks if r.risk_level == 'Medium']),
                'low': len([r for r in identity_risks if r.risk_level == 'Low'])
            },
            'permission_risks': {
                'total': len(permission_risks),
                'high': len([r for r in permission_risks if r.risk_level == 'High']),
                'medium': len([r for r in permission_risks if r.risk_level == 'Medium']),
                'low': len([r for r in permission_risks if r.risk_level == 'Low'])
            }
        }
        
        return jsonify({
            'success': True,
            'data': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments/<int:assessment_id>', methods=['PUT'])
def update_assessment(assessment_id):
    """Update an assessment"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        data = request.json
        
        # Update allowed fields
        if 'name' in data:
            assessment.name = data['name']
        if 'status' in data:
            assessment.status = data['status']
            if data['status'] == 'completed':
                assessment.completed_at = datetime.utcnow()
        if 'total_identities' in data:
            assessment.total_identities = data['total_identities']
        if 'high_risk_items' in data:
            assessment.high_risk_items = data['high_risk_items']
        if 'zero_trust_score' in data:
            assessment.zero_trust_score = data['zero_trust_score']
        if 'maturity_level' in data:
            assessment.maturity_level = data['maturity_level']
        if 'config' in data:
            assessment.config_json = json.dumps(data['config'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': assessment.to_dict(),
            'message': 'Assessment updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments/<int:assessment_id>', methods=['DELETE'])
def delete_assessment(assessment_id):
    """Delete an assessment and all related data"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Delete related data (handled by cascade)
        db.session.delete(assessment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Assessment deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments/<int:assessment_id>/modules', methods=['GET'])
def get_assessment_modules(assessment_id):
    """Get all modules for a specific assessment"""
    try:
        Assessment.query.get_or_404(assessment_id)  # Verify assessment exists
        
        modules = AssessmentModule.query.filter_by(assessment_id=assessment_id).all()
        
        return jsonify({
            'success': True,
            'data': [module.to_dict() for module in modules],
            'count': len(modules)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments/<int:assessment_id>/modules/<int:module_id>', methods=['PUT'])
def update_assessment_module(assessment_id, module_id):
    """Update a specific assessment module"""
    try:
        module = AssessmentModule.query.filter_by(
            id=module_id, 
            assessment_id=assessment_id
        ).first_or_404()
        
        data = request.json
        
        # Update allowed fields
        if 'status' in data:
            module.status = data['status']
            if data['status'] == 'running':
                module.started_at = datetime.utcnow()
            elif data['status'] == 'completed':
                module.completed_at = datetime.utcnow()
        
        if 'results' in data:
            module.results_json = json.dumps(data['results'])
        
        if 'error_message' in data:
            module.error_message = data['error_message']
        
        if 'items_analyzed' in data:
            module.items_analyzed = data['items_analyzed']
        
        if 'high_risk_count' in data:
            module.high_risk_count = data['high_risk_count']
        
        if 'medium_risk_count' in data:
            module.medium_risk_count = data['medium_risk_count']
        
        if 'low_risk_count' in data:
            module.low_risk_count = data['low_risk_count']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': module.to_dict(),
            'message': 'Module updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments/<int:assessment_id>/recommendations', methods=['GET'])
def get_assessment_recommendations(assessment_id):
    """Get all recommendations for a specific assessment"""
    try:
        Assessment.query.get_or_404(assessment_id)  # Verify assessment exists
        
        # Query parameters
        priority = request.args.get('priority')
        status = request.args.get('status')
        category = request.args.get('category')
        
        query = Recommendation.query.filter_by(assessment_id=assessment_id)
        
        if priority:
            query = query.filter(Recommendation.priority == priority)
        if status:
            query = query.filter(Recommendation.status == status)
        if category:
            query = query.filter(Recommendation.category.ilike(f'%{category}%'))
        
        # Order by priority (Critical, High, Medium, Low)
        priority_order = ['Critical', 'High', 'Medium', 'Low']
        query = query.order_by(
            db.case(
                [(Recommendation.priority == p, i) for i, p in enumerate(priority_order)],
                else_=len(priority_order)
            )
        )
        
        recommendations = query.all()
        
        return jsonify({
            'success': True,
            'data': [rec.to_dict() for rec in recommendations],
            'count': len(recommendations)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments/<int:assessment_id>/recommendations', methods=['POST'])
def create_recommendation(assessment_id):
    """Create a new recommendation for an assessment"""
    try:
        Assessment.query.get_or_404(assessment_id)  # Verify assessment exists
        
        data = request.json
        
        # Validate required fields
        required_fields = ['category', 'priority', 'issue', 'recommendation']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        recommendation = Recommendation(
            assessment_id=assessment_id,
            category=data['category'],
            priority=data['priority'],
            issue=data['issue'],
            recommendation=data['recommendation'],
            zero_trust_principle=data.get('zero_trust_principle'),
            implementation_steps=json.dumps(data.get('implementation_steps', [])),
            affected_count=data.get('affected_count', 0),
            estimated_effort=data.get('estimated_effort'),
            assigned_to=data.get('assigned_to'),
            due_date=datetime.fromisoformat(data['due_date']) if data.get('due_date') else None,
            notes=data.get('notes')
        )
        
        db.session.add(recommendation)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': recommendation.to_dict(),
            'message': 'Recommendation created successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/recommendations/<int:recommendation_id>', methods=['PUT'])
def update_recommendation(recommendation_id):
    """Update a specific recommendation"""
    try:
        recommendation = Recommendation.query.get_or_404(recommendation_id)
        data = request.json
        
        # Update allowed fields
        if 'status' in data:
            recommendation.status = data['status']
            if data['status'] == 'completed':
                recommendation.completed_at = datetime.utcnow()
        
        if 'assigned_to' in data:
            recommendation.assigned_to = data['assigned_to']
        
        if 'due_date' in data:
            recommendation.due_date = datetime.fromisoformat(data['due_date']) if data['due_date'] else None
        
        if 'notes' in data:
            recommendation.notes = data['notes']
        
        if 'priority' in data:
            recommendation.priority = data['priority']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': recommendation.to_dict(),
            'message': 'Recommendation updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@assessment_bp.route('/assessments/<int:assessment_id>/summary', methods=['GET'])
def get_assessment_summary(assessment_id):
    """Get a summary of assessment results"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Get module statistics
        modules = AssessmentModule.query.filter_by(assessment_id=assessment_id).all()
        module_stats = {
            'total': len(modules),
            'completed': len([m for m in modules if m.status == 'completed']),
            'running': len([m for m in modules if m.status == 'running']),
            'pending': len([m for m in modules if m.status == 'pending']),
            'failed': len([m for m in modules if m.status == 'failed'])
        }
        
        # Get recommendation statistics
        recommendations = Recommendation.query.filter_by(assessment_id=assessment_id).all()
        rec_stats = {
            'total': len(recommendations),
            'critical': len([r for r in recommendations if r.priority == 'Critical']),
            'high': len([r for r in recommendations if r.priority == 'High']),
            'medium': len([r for r in recommendations if r.priority == 'Medium']),
            'low': len([r for r in recommendations if r.priority == 'Low']),
            'open': len([r for r in recommendations if r.status == 'open']),
            'in_progress': len([r for r in recommendations if r.status == 'in_progress']),
            'completed': len([r for r in recommendations if r.status == 'completed'])
        }
        
        # Get risk statistics
        identity_risks = IdentityRisk.query.filter_by(assessment_id=assessment_id).all()
        permission_risks = PermissionRisk.query.filter_by(assessment_id=assessment_id).all()
        
        risk_stats = {
            'identity_risks': {
                'total': len(identity_risks),
                'high': len([r for r in identity_risks if r.risk_level == 'High']),
                'medium': len([r for r in identity_risks if r.risk_level == 'Medium']),
                'low': len([r for r in identity_risks if r.risk_level == 'Low']),
                'privileged': len([r for r in identity_risks if r.is_privileged]),
                'stale': len([r for r in identity_risks if r.is_stale])
            },
            'permission_risks': {
                'total': len(permission_risks),
                'high': len([r for r in permission_risks if r.risk_level == 'High']),
                'medium': len([r for r in permission_risks if r.risk_level == 'Medium']),
                'low': len([r for r in permission_risks if r.risk_level == 'Low']),
                'anonymous_access': len([r for r in permission_risks if r.has_anonymous_access]),
                'broad_access': len([r for r in permission_risks if r.has_broad_access])
            }
        }
        
        summary = {
            'assessment': assessment.to_dict(),
            'modules': module_stats,
            'recommendations': rec_stats,
            'risks': risk_stats,
            'completion_percentage': (module_stats['completed'] / module_stats['total'] * 100) if module_stats['total'] > 0 else 0
        }
        
        return jsonify({
            'success': True,
            'data': summary
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

