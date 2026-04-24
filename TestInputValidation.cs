using NUnit.Framework;

namespace SecurityAndAuth
{
    [TestFixture]
    public class TestInputValidation
    {
        // ✅ VALID INPUT TESTS

        [Test]
        public void ValidFullName_ShouldPass()
        {
            var result = InputValidator.IsValidFullName("John Doe");
            Assert.IsTrue(result);
        }

        [Test]
        public void ValidEmail_ShouldPass()
        {
            var result = InputValidator.IsValidEmail("john@example.com");
            Assert.IsTrue(result);
        }

        [Test]
        public void ValidPassword_ShouldPass()
        {
            var result = InputValidator.IsValidPassword("Secure123!");
            Assert.IsTrue(result);
        }

        // ❌ INVALID INPUT TESTS

        [Test]
        public void InvalidFullName_ShouldFail()
        {
            var result = InputValidator.IsValidFullName("J@hn123");
            Assert.IsFalse(result);
        }

        [Test]
        public void InvalidEmail_ShouldFail()
        {
            var result = InputValidator.IsValidEmail("invalid-email");
            Assert.IsFalse(result);
        }

        [Test]
        public void WeakPassword_ShouldFail()
        {
            var result = InputValidator.IsValidPassword("123");
            Assert.IsFalse(result);
        }

        // 🔴 SQL INJECTION TEST

        [Test]
        public void SQLInjection_ShouldBeDetected()
        {
            string maliciousInput = "DROP TABLE Users;";

            var result = InputValidator.ContainsSqlInjection(maliciousInput);

            Assert.IsTrue(result);
        }

        // 🔴 XSS TEST

        [Test]
        public void XSS_ShouldBeDetected()
        {
            string xssInput = "<script>alert('hack')</script>";

            var result = InputValidator.ContainsXss(xssInput);

            Assert.IsTrue(result);
        }

        // ❌ EDGE CASES

        [Test]
        public void EmptyName_ShouldFail()
        {
            var result = InputValidator.IsValidFullName("");
            Assert.IsFalse(result);
        }

        [Test]
        public void NullEmail_ShouldFail()
        {
            var result = InputValidator.IsValidEmail(null);
            Assert.IsFalse(result);
        }
    }
}
