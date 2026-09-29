
import urllib.request, json
with open('rubric.txt', 'r', encoding='utf-8') as f:
    prompt = f.read() + '
now give me the  output'
data = json.dumps({'prompt': prompt}).encode('utf-8')
req = urllib.request.Request('http://127.0.0.1:8001/chat', data=data, headers={'Content-Type': 'application/json'})
response = urllib.request.urlopen(req)
print(json.loads(response.read().decode('utf-8'))['reply'])

