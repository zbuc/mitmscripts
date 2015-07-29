import string

from libmproxy.protocol.http import decoded

from bs4 import BeautifulSoup

def piglify(src):
    words = string.split(src)
    ret = ''
    for word in words:
        idx = -1;
        while word[idx] in string.punctuation and (idx * -1) != len(word): idx -= 1
        if word[0].lower() in 'aeiou':
            if idx == -1: ret += word[0:] + "hay"
            else: ret += word[0:len(word)+idx+1] + "hay" + word[idx+1:]
        else:
            if idx == -1: ret += word[1:] + word[0] + "ay"
            else: ret += word[1:len(word)+idx+1] + word[0] + "ay" + word[idx+1:]
        ret += ' '
    return ret.strip()

def piglify_request(context, flow):
    print "Piglifying Request"
    with decoded(flow.request):
        flow.request.content = str(piglify(flow.request.content).encode('utf-8'))

def piglify_response(context, flow):
    with decoded(flow.response):
        html_response = False
        for header in flow.response.headers:
            if header[0] == 'Content-Type' and 'text/html' in header[1]:
                html_response = True

        if not html_response:
            print "Not piglifying response without text/html Content-Type header"
            return

        print "Piglifying Response"

        soup = BeautifulSoup(flow.response.content, 'html.parser')
        replace = []
        for text in soup._all_strings():
            replace.append(text)

        for text in replace:
            if soup.find(text=text):
                soup.find(text=text).replaceWith(piglify(text))

        flow.response.content = str(soup.prettify().encode('utf-8'))

def start(context, argv):
    def hexdump(src, length=8):
        result = []
        digits = 4 if isinstance(src, unicode) else 2
        for i in xrange(0, len(src), length):
            s = src[i:i+length]
            hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
            text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
            result.append(b"%04X   %-*s   %s" %
                         (i, length * (digits + 1), hexa, text))
        return b'\n'.join(result)

    # plugins are currently only supported on the WebMaster class
    if hasattr(context, 'plugins') and context.plugins:
        context.plugins.register_view('hex',
                                      title='Hex View Plugin',
                                      transformer=hexdump)

        context.plugins.register_action('piglify',
                                        title='Pig Latin Plugin',
                                        actions=[{
                                                  'title': 'Piglify Request',
                                                  'id': 'piglify_request',
                                                  'possible_hooks': ['request'],
                                                 },
                                                 {
                                                  'title': 'Piglify Response',
                                                  'id': 'piglify_response',
                                                  'state': {
                                                    'every_flow': True,
                                                  },
                                                  'possible_hooks': ['response'],
                                                 },
                                                 { 
                                                  'title': 'Puglify Image',
                                                  'id': 'puglify_image',
                                                  'possible_hooks': ['response'],
                                                 },
                                                 ])
