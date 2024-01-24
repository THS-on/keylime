import argparse
import asyncio
import json
import logging
import signal
import traceback
from typing import Any

import tornado
from tornado.web import Application, RequestHandler

from keylime.agentstates import AgentAttestState
from keylime.common import algorithms
from keylime.ima import ima
from keylime.ima.file_signatures import ImaKeyrings
from keylime.mba import mba

mba.load_imports()
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")


class BaseHandler(RequestHandler):
    def return_json(self, data, code):
        json_response_bytes = json.dumps(data)
        self.set_status(code)
        self.set_header("Content-Type", "application/json")
        self.write(json_response_bytes)
        self.finish()


class MeasuredBootValidationHandler(BaseHandler):
    def post(self):
        try:
            data = json.loads(self.request.body.decode("utf-8"))
            agent_id = data["agent_id"]
            hash_alg = data["hash_alg"]
            mb_refstate = data["mb_refstate"]
            mb_measurement_list = data["mb_measurement_list"]
            pcrs_inquote = set([int(x) for x in data["pcrs_inquote"]])
        except ValueError as e:
            self.return_json({"error": f"Unexpected payload format: {e}"}, 422)
            return
        mb_pcrs_hashes, boot_aggregates, mb_measurement_data, mb_parse_failure = mba.bootlog_parse(
            mb_measurement_list, hash_alg
        )
        if mb_parse_failure:
            self.return_json({"error": f"Parser error: {mb_parse_failure.get_event_ids()}"}, 422)
            return
        mb_failure = mba.bootlog_evaluate(mb_refstate, mb_measurement_data, pcrs_inquote, agent_id)
        failure = None
        if mb_failure:
            failure = mb_failure.highest_severity_event.event_id
        # Convert to hex values
        mb_pcrs_hashes = {k: hex(v)[2:] for k, v in mb_pcrs_hashes.items()}
        response = {"failure": failure, "mb_pcrs_hashes": mb_pcrs_hashes, "boot_aggregates": boot_aggregates}
        self.return_json(response, 200)


class IMAHandler(BaseHandler):
    def post(self):
        logging.info("Got IMA request")
        try:
            try:
                data = json.loads(self.request.body.decode("utf-8"))
                agent_id = data["agent_id"]
                hash_alg = algorithms.Hash(data["hash_alg"])
                ima_measurement_list = data["ima_measurement_list"]
                runtime_policy = json.loads(data["runtime_policy"])
                pcrval = data["pcrval"]
                boot_aggregates = None
            except ValueError as e:
                logging.info(f"Key error {e}")
                self.return_json({"error": f"Unexpected payload format: {e}"}, 422)
                return

            agentAttestState = AgentAttestState(agent_id)
            ima_keyrings = ImaKeyrings()

            _, ima_failure = ima.process_measurement_list(
                agentAttestState,
                ima_measurement_list.split("\n"),
                runtime_policy,
                pcrval=pcrval,
                ima_keyrings=ima_keyrings,
                boot_aggregates=boot_aggregates,
                hash_alg=hash_alg,
            )

            failure = None
            response = {}
            if ima_failure:
                failure = ima_failure.highest_severity_event.event_id
                response["context"] = ima_failure.highest_severity_event.context
            response["failure"] = failure

            self.return_json(response, 200)
        except Exception as e:
            self.return_json({"error": f"Unexpected error: {traceback.format_exc()}"}, 422)
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("port")
    args = parser.parse_args()

    app = Application([(r"/mb/validate", MeasuredBootValidationHandler), (r"/ima/validate", IMAHandler)])
    sockets = tornado.netutil.bind_sockets(int(args.port))
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)

    def server_sig_handler(*_: Any) -> None:
        server.stop()

        # Wait for all connections to be closed and then stop ioloop
        async def stop() -> None:
            await server.close_all_connections()
            tornado.ioloop.IOLoop.current().stop()

        asyncio.ensure_future(stop())

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, server_sig_handler)
    loop.add_signal_handler(signal.SIGTERM, server_sig_handler)

    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
