namespace authProjet.Services
{
    public interface IAuthService
    {
        Task<(bool success, string token)> LoginAsync(string email, string password);
        Task<(bool success, string message)> RegisterAsync(string email, string password, string firstName, string lastName);
    }
}