from flask_restx import Namespace, Resource, fields
from ..services.jobs import JobManager
ns = Namespace('jobs', description='Async jobs'); jobman = JobManager()
status_model = ns.model('JobStatus', {'state': fields.String, 'result': fields.Raw, 'error': fields.String})
@ns.route('/jobs/<string:job_id>')
class Job(Resource):
    @ns.marshal_with(status_model, code=200, skip_none=True)
    def get(self, job_id): return jobman.status(job_id)
