from concurrent.futures import ThreadPoolExecutor, Future
import uuid
class JobManager:
    def __init__(self, max_workers=4):
        self.pool = ThreadPoolExecutor(max_workers=max_workers)
        self.jobs: dict[str, Future] = {}
    def submit(self, fn, *args, **kwargs) -> str:
        jid = uuid.uuid4().hex
        self.jobs[jid] = self.pool.submit(fn, *args, **kwargs)
        return jid
    def status(self, job_id: str):
        fut = self.jobs.get(job_id)
        if not fut: return {"state":"unknown"}
        if fut.running(): return {"state":"running"}
        if fut.done():
            ex = fut.exception()
            if ex: return {"state":"error","error":str(ex)}
            return {"state":"completed","result":fut.result()}
        return {"state":"queued"}
