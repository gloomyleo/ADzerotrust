from flask_restx import Namespace, Resource, fields
from ..services.config import load_config
from ..services.zero_trust_engine import ZeroTrustEngine
from ..services.evidence_export import export_pdf
from .jobs import jobman
ns = Namespace('checks', description='Run checks')
run_req = ns.model('RunRequest', {'signed_only': fields.Boolean(default=True)})
run_resp = ns.model('RunResponse', {'job_id': fields.String})
def _run():
    CONF=load_config(); eng=ZeroTrustEngine(CONF); res=eng.run_checks(signed_only=True)
    export_pdf(CONF.get('app',{}).get('out_dir','out')); return res
@ns.route('/run_checks')
class Run(Resource):
    @ns.expect(run_req, validate=False)
    @ns.marshal_with(run_resp, code=202)
    def post(self): jid=jobman.submit(_run); return {'job_id': jid}, 202
