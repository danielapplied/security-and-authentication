using BCrypt.Net;

public class AuthService
{
    private readonly UserRepository _repo;

    public AuthService(UserRepository repo)
    {
        _repo = repo;
    }

    // Register user (hash password)
    public void Register(string username, string email, string password, string role = "USER")
    {
        var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

        _repo.InsertUserWithPassword(username, email, hashedPassword, role);
    }

    // Authenticate login
    public bool Login(string username, string password)
    {
        var user = _repo.GetUserWithPassword(username);

        if (user == null)
            return false;

        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
    }
}
