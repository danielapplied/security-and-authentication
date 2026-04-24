using NUnit.Framework;

namespace SecurityAndAuth
{
    [TestFixture]
    public class XSSTest
    {
        // 🔴 Detect raw XSS input
        [Test]
        public void Should_Detect_Basic_XSS_Script()
        {
            string input = "<script>alert('hack')</script>";

            bool result = InputValidator.ContainsXss(input);

            Assert.IsTrue(result);
        }

        // 🔴 Detect encoded/obfuscated XSS
        [Test]
        public void Should_Detect_Complex_XSS()
        {
            string input = "<img src=x onerror=alert('xss')>";

            bool result = InputValidator.ContainsXss(input);

            Assert.IsTrue(result);
        }

        // ✅ Ensure safe input passes
        [Test]
        public void Safe_Input_Should_Not_Be_Flagged()
        {
            string input = "John Doe";

            bool result = InputValidator.ContainsXss(input);

            Assert.IsFalse(result);
        }

        // 🔒 Test HTML Encoding (actual XSS prevention)
        [Test]
        public void Should_Encode_XSS_Input()
        {
            string input = "<script>alert('hack')</script>";

            string encoded = InputSanitizer.EncodeForHtml(input);

            Assert.IsFalse(encoded.Contains("<script>"));
            Assert.IsTrue(encoded.Contains("&lt;script&gt;"));
        }

        // 🔴 Edge Case: Empty input
        [Test]
        public void Empty_Input_Should_Not_Be_Flagged()
        {
            string input = "";

            bool result = InputValidator.ContainsXss(input);

            Assert.IsFalse(result);
        }

        // 🔴 Null input
        [Test]
        public void Null_Input_Should_Not_Be_Flagged()
        {
            string input = null;

            bool result = InputValidator.ContainsXss(input);

            Assert.IsFalse(result);
        }
    }
}
