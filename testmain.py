import unittest
from unittest.mock import patch
import re
from io import StringIO
from itertools import cycle
from mainn import (
    random_string,
    obfuscate_word_case,
    add_backticks_to_word,
    obfuscate_variables,
    obfuscate_functions,
    obfuscate_cmdlets,
    obfuscate_namespaces,
    obfuscate_comments,
    obfuscate_pipes,
    obfuscate_indentation,
    obfuscate_ips,
)

class TestObfuscationFunctions(unittest.TestCase):

    def test_random_string(self):
        """Test to ensure random_string generates a string of the correct length"""
        for length in [5, 10, 15]:
            generated = random_string(length)
            self.assertEqual(len(generated), length)
            self.assertTrue(all(c.isalpha() for c in generated))

    def test_obfuscate_word_case(self):
        """Test to verify word case obfuscation alternates cases randomly"""
        word = "PowerShell"
        obfuscated = obfuscate_word_case(word)
        self.assertNotEqual(obfuscated, word)
        self.assertEqual(len(obfuscated), len(word))
        self.assertTrue(any(c.islower() for c in obfuscated) and any(c.isupper() for c in obfuscated))

    def test_add_backticks_to_word(self):
        """Test that add_backticks_to_word inserts backticks in appropriate places"""
        word = "Invoke"
        obfuscated = add_backticks_to_word(word)
        self.assertNotEqual(obfuscated, word)
        for char in word:
            self.assertIn(char, obfuscated)


    def test_obfuscate_functions(self):
        """Test function name obfuscation"""
        content = "function TestFunction { Write-Output 'Hello' } function AnotherFunction { Write-Output 'Bye' }"
        obfuscated = obfuscate_functions(content)
        self.assertNotIn("TestFunction", obfuscated)
        self.assertNotIn("AnotherFunction", obfuscated)

    def test_obfuscate_cmdlets(self):
        """Test cmdlet obfuscation for known cmdlets"""
        content = "Get-Content -Path 'file.txt'; Invoke-Expression -Command 'Hello'"
        obfuscated = obfuscate_cmdlets(content)
        for cmdlet in ["Get-Content", "Invoke-Expression"]:
            self.assertNotIn(cmdlet, obfuscated)
            self.assertTrue(any(c in obfuscated for c in "`"), "Backticks should be present")

    def test_obfuscate_namespaces(self):
        """Test namespace obfuscation for known namespaces"""
        content = "System.IO.StreamWriter; System.Net.Sockets.TcpClient"
        obfuscated = obfuscate_namespaces(content)
        for namespace in ["System.IO.StreamWriter", "System.Net.Sockets.TcpClient"]:
            self.assertNotIn(namespace, obfuscated)

    def test_obfuscate_comments(self):
        """Test that comments are removed"""
        content = "# This is a comment\nGet-Content -Path 'file.txt' # Another comment"
        obfuscated = obfuscate_comments(content)
        self.assertNotIn("#", obfuscated)

    def test_obfuscate_pipes(self):
        """Test pipe obfuscation"""
        content = "Get-Content -Path 'file.txt' | Select-Object -First 1"
        obfuscated = obfuscate_pipes(content)
        self.assertIn("%{$_}", obfuscated)

    def test_obfuscate_indentation(self):
        """Test that random indentation is added"""
        content = "Get-Content -Path 'file.txt'\nInvoke-Expression 'Hello'"
        obfuscated = obfuscate_indentation(content)
        lines = obfuscated.splitlines()
        for line in lines:
            self.assertTrue(line.startswith(" ") or line.strip() == "Get-Content -Path 'file.txt'" or line.strip() == "Invoke-Expression 'Hello'")

    def test_obfuscate_ips(self):
        """Test that IP addresses are converted to hex"""
        content = "Connect-Computer -IPAddress 192.168.1.1"
        obfuscated = obfuscate_ips(content)
        self.assertNotIn("192.168.1.1", obfuscated)
        self.assertIn("0x", obfuscated)  
    def test_random_string_empty(self):
        """Test to ensure random_string handles a length of 0"""
        generated = random_string(0)
        self.assertEqual(generated, "")

    def test_obfuscate_word_case_no_alphabet(self):
        """Test to ensure obfuscate_word_case handles words without alphabetic characters"""
        word = "12345!@#"
        obfuscated = obfuscate_word_case(word)
        self.assertEqual(obfuscated, word)  

    
    @patch("random.choice", side_effect=cycle([True, False]))
    def test_obfuscate_word_case_deterministic(self, mock_choice):
        """Test obfuscate_word_case with mocked randomness to ensure predictable output"""
        word = "Test"
        obfuscated = obfuscate_word_case(word)
        self.assertEqual(obfuscated, "TeSt")
    def test_add_backticks_to_special_chars(self):
        """Ensure add_backticks_to_word handles words with special characters correctly"""
        word = "Invoke&Cmdlet"
        obfuscated = add_backticks_to_word(word)
        self.assertIn("&", obfuscated)
        self.assertNotIn("`&", obfuscated)

    def test_obfuscate_comments_empty(self):
        """Test that obfuscate_comments handles empty content"""
        content = ""
        obfuscated = obfuscate_comments(content)
        self.assertEqual(obfuscated, "")

    def test_integration_all_obfuscations(self):
        """Test a sample content with all obfuscation functions combined"""
        content = """
        function TestFunc { Write-Output "Hello World" }
        $var = "192.168.0.1"
        # This is a comment
        Get-Content -Path 'file.txt' | Select-Object -First 1
        """
        content = obfuscate_comments(content)
        content = obfuscate_variables(content)
        content = obfuscate_functions(content)
        content = obfuscate_cmdlets(content)
        content = obfuscate_namespaces(content)
        content = obfuscate_pipes(content)
        content = obfuscate_ips(content)
        content = obfuscate_indentation(content)

        self.assertNotIn("TestFunc", content)
        self.assertNotIn("192.168.0.1", content)
        self.assertNotIn("Get-Content", content)
        self.assertNotIn("# This is a comment", content)
        self.assertIn("%{$_}", content)  

if __name__ == "__main__":
    unittest.main()
