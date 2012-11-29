import unittest
from firewall import *

class TestFirewall(unittest.TestCase):
    
    def setUp(self):
        self.fw = firewall.Firewall()

    def test_match(self):
        string = "HOST: www.google.com \n"
        regex = r'HOST:\s*(\S*)\s* \n'
        string_match = self.fw.match(string, regex)
        print string_match
        assert string_match != 'No match found'

if __name__=='main':
    unittest.main()
