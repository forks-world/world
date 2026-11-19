"""Scripted OpenAI-compatible model endpoint for the development preview.

The real CLI agent executes the tools. This fixture makes the sequence of tool
requests reproducible without sending the project or credentials to a provider.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json


PORT = 18767
TEMPLATE = '/workspace/flaskr/templates/base.html'
OLD = '>Flaskr</a></h1>'
NEW = '>Flaskr World Preview</a></h1>'
BASH = 'pwd && /home/world/preview-venv/bin/python -m pytest -q'


class Model(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.end_headers()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != '/v1/chat/completions':
            self.send_error(404)
            return
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 2_000_000:
            self.send_error(413)
            return
        request = json.loads(self.rfile.read(length))
        results = [json.dumps(item.get('content', '')) for item in request['messages']
                   if item['role'] == 'tool']
        cases = [
            ('read', {'filePath': TEMPLATE}),
            ('edit', {'filePath': TEMPLATE, 'oldString': OLD, 'newString': NEW}),
            ('bash', {'command': BASH, 'description': 'Run Flaskr tests inside /workspace',
                      'workdir': '/workspace', 'timeout': 60000}),
        ]
        tools = {tool['function']['name'] for tool in request.get('tools', [])
                 if tool.get('type') == 'function'}
        number = len(results)
        if not tools:
            # The CLI also requests a title using the model but without tools.
            message, reason = {'content': 'Flaskr development preview'}, 'stop'
        else:
            if number >= 1 and OLD not in results[0]:
                self.send_error(400, 'the file read did not return the Flaskr template')
                return
            if number >= 3 and not all(value in results[2] for value in ('/workspace', '24 passed')):
                print(f'unexpected bash result: {results[2][:1500]}', flush=True)
                self.send_error(400, 'the bash tool did not confirm test success')
                return
            if number <= 2:
                name, arguments = cases[number]
                if name not in tools:
                    self.send_error(400, f'expected agent tool is unavailable: {name}')
                    return
                tool = {'id': f'call_preview_{number}', 'type': 'function',
                        'function': {'name': name, 'arguments': json.dumps(arguments)}}
                message, reason = {'tool_calls': [tool]}, 'tool_calls'
            else:
                message = {'content': 'The Flaskr heading was updated and the guest tests passed.'}
                reason = 'stop'
            print(f'model round {number}: {reason}', flush=True)
        header = {'id': f'chatcmpl-preview-{number}', 'created': 1, 'model': 'fixture'}
        if request.get('stream'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            if 'tool_calls' in message:
                message['tool_calls'][0]['index'] = 0
            chunk = dict(header, object='chat.completion.chunk')
            for delta, finish in [({'role': 'assistant', **message}, None), ({}, reason)]:
                body = dict(chunk, choices=[{'index': 0, 'delta': delta, 'finish_reason': finish}])
                self.wfile.write(b'data: ' + json.dumps(body).encode() + b'\n\n')
            self.wfile.write(b'data: [DONE]\n\n')
        else:
            body = dict(header, object='chat.completion',
                        choices=[{'index': 0, 'message': {'role': 'assistant', **message},
                                  'finish_reason': reason}])
            encoded = json.dumps(body).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)


if __name__ == '__main__':
    HTTPServer(('127.0.0.1', PORT), Model).serve_forever()
