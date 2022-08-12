using Auth_JWT.JWT;
using Auth_JWT.Model;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Driver;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Auth_JWT.Repository
{
    public class UserRepository : IUserRepository
    {
        private readonly IMongoCollection<Session> _sessionsCollection;
        private readonly IMongoCollection<User> _usersCollection;

        public UserRepository(IMongoClient mongoClient)
        {
            var camelCaseConvention = new ConventionPack { new CamelCaseElementNameConvention() };
            ConventionRegistry.Register("CamelCase", camelCaseConvention, type => true);

            _usersCollection = mongoClient.GetDatabase("sample_mflix").GetCollection<User>("users");
            _sessionsCollection = mongoClient.GetDatabase("sample_mflix").GetCollection<Session>("sessions");
        }

        public async Task<UserResponse> AddUserAsync(string name, string email, string password)
        {
            try
            {
                var user = new User();
                user = new User { Name = name, Email = email, HashedPassword = PasswordHashOMatic.Hash(password) };
                await _usersCollection.InsertOneAsync(user);
                var newUser = await GetUserAsync(user.Email);
                return new UserResponse(newUser);
            }
            catch (Exception ex)
            {
                return ex.Message.StartsWith("MongoError: E11000 duplicate key error")
                    ? new UserResponse(false, "A user with the given email already exists.")
                    : new UserResponse(false, ex.Message);
            }
        }

        public async Task<UserResponse> DeletUserAsync(string email)
        {
            try
            {
                await _usersCollection.DeleteOneAsync<User>(u => u.Email == email);
                await _sessionsCollection.DeleteOneAsync(new BsonDocument("user_id", email));
                var deletedUser = await _usersCollection.FindAsync<User>(u => u.Email == email);
                var deletedSession = await _sessionsCollection.FindAsync<Session>(new BsonDocument("user_id", email));
                if (deletedUser.FirstOrDefault() == null && deletedSession.FirstOrDefault() == null)
                    return new UserResponse(true, "User deleted");
                return new UserResponse(false, "User deletion was unsuccessful");

            }
            catch(Exception ex)
            {
                return new UserResponse(false, ex.ToString());

            }
        }

        public async Task<Session> GetSessionAsync(string email)
        {
            return await _sessionsCollection.Find<Session>(new BsonDocument("user_id", email)).FirstOrDefaultAsync();
        }

        public async Task<User> GetUserAsync(string email)
        {
            User result = await _usersCollection.Find(Builders<User>.Filter.Eq(u => u.Email, email)).FirstOrDefaultAsync();
            return result;
        }

        public async Task<UserResponse> LoginUserAsync(User user)
        {
            try
            {
                var storedUser = await GetUserAsync(user.Email);
                if (storedUser == null)
                {
                    return new UserResponse(false, "No user found. Please check the email address.");
                }
                if (user.HashedPassword != null && user.HashedPassword != storedUser.HashedPassword)
                {
                    return new UserResponse(false, "The hashed password provided is not valid");
                }
                if (user.HashedPassword == null && !PasswordHashOMatic.Verify(user.Password, storedUser.HashedPassword))
                {
                    return new UserResponse(false, "The password provided is not valid");
                }
                await _sessionsCollection.UpdateOneAsync(
                 new BsonDocument("user_id", user.Email),
                 Builders<Session>.Update.Set(s => s.UserId, user.Email).Set(s => s.Jwt, user.AuthToken));
                storedUser.AuthToken = user.AuthToken;
                return new UserResponse(storedUser);
            }
            catch (Exception ex)
            {
                return new UserResponse(false, ex.Message);
            }
        }

        public async Task<UserResponse> LogoutUserAsync(string email)
        {
            await _sessionsCollection.DeleteOneAsync(new BsonDocument("email", email));
            return new UserResponse(true, "User logged out.");
        }

        public async Task<User> MakeAdminUser(User user)
        {
            user.IsAdmin = true;
            await _usersCollection.InsertOneAsync(user);
            return await GetUserAsync(user.Email);
        }

    }
}
