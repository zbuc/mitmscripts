import string
import cStringIO
import inspect
import os

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


def piglify_response(context, flow):
    with decoded(flow.response):
        html_response = False
        for header in flow.response.headers:
            if header[0] == 'Content-Type' and 'text/html' in header[1]:
                html_response = True

        if not html_response:
            return

        soup = BeautifulSoup(flow.response.content, 'html.parser')
        replace = []
        for text in soup._all_strings():
            replace.append(text)

        for text in replace:
            if soup.find(text=text):
                soup.find(text=text).replaceWith(piglify(text))

        flow.response.content = str(soup.prettify().encode('utf-8'))


def disable_cache(context, flow):
    with decoded(flow.request):
        flow.request.headers['Cache-Control'] = ['no-cache']
        flow.request.headers['If-Modified-Since'] = []


def puglify_image(context, flow):
    with decoded(flow.response):
        try:
            if flow.response.headers.get_first("content-type", "").startswith("image") or flow.response.content.startswith("\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00"):
                img = cStringIO.StringIO(open(os.path.normcase(os.path.dirname(inspect.stack()[0][1]) + '/pug.jpg'), 'rb').read())
                flow.response.content = img.getvalue()
                flow.response.headers["content-type"] = ["image/jpeg"]
        except Exception, e:
            print "Error puglifying:"
            print repr(e)


def colorify(context, flow):
    with decoded(flow.response):
        try:
            color = context.plugins.get_option_value('colorswitcher', 'color')
            css_response = False
            for header in flow.response.headers:
                if header[0].lower() == 'content-type' and ('css' in header[1].lower() or 'html' in header[1].lower()):
                    css_response = True
            for header in flow.request.headers:
                if header[0].lower() == 'accept' and ('css' in header[1].lower() or 'html' in header[1].lower()):
                    css_response = True

            if not css_response:
                return

            import re
            pattern_hex = re.compile('#[0-9]+', re.IGNORECASE)
            flow.response.content = pattern_hex.sub(color, flow.response.content)
        except Exception, e:
            print "Error colorifying:"
            print repr(e)


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

        context.plugins.register_action('colorswitcher',
                                        title='Color Switcher',
                                        options=[{
                                            'title': 'Color',
                                            'id': 'color',
                                            'state': {
                                                'value': '#EA5C7A',
                                            },
                                            'type': 'text',
                                        }],
                                        actions=[{
                                            'title': 'Colorify',
                                            'id': 'colorify',
                                            'state': {
                                                'every_flow': True,
                                            },
                                            'possible_hooks': ['response'],
                                        },
                                        {
                                            'title': 'Disable Cache',
                                            'id': 'disable_cache',
                                            'state': {
                                                'every_flow': True,
                                            },
                                            'possible_hooks': ['request'],
                                        }
                                        ])

        context.plugins.register_action('piglify',
                                        title='P[iu]g Latin Plugin',
                                        actions=[
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
                                                  'state': {
                                                    'every_flow': True,
                                                    },

                                                 },
                                                 ])
