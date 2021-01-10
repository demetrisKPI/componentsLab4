using System;
using Xunit;
using IIG.CoSFE.DatabaseUtils;
using IIG.BinaryFlag;
using IIG.DatabaseConnectionUtils;
using IIG.FileWorker;
using IIG.PasswordHashingUtils;

namespace Test
{
    public class PasswordHasherTest
    {
        private string path = BaseFileWorker.MkDir("FileWorker");

        [Fact]
        public void TestGetHash()
        {
            string password = PasswordHasher.GetHash("password", "password");
            BaseFileWorker.Write(password, path + "\\" + "test.txt");
            Assert.Equal(password, BaseFileWorker.ReadAll(path + "\\" + "test.txt"));
        }

        [Fact]
        public void TestGetHashEmptyString()
        {
            string password = PasswordHasher.GetHash(string.Empty, string.Empty);
            BaseFileWorker.Write(string.Empty, path + "\\" + "test.txt");
            string password2 = PasswordHasher.GetHash(BaseFileWorker.ReadAll(path + "\\" + "test.txt"));
            Assert.Equal(password, password2);
        }

        [Fact]
        public void TestGetHashSymbols()
        {
            string symbols = "!@#$%^&*()_+-=,./;'[]|}{:";
            string password = PasswordHasher.GetHash(symbols, symbols);
            BaseFileWorker.Write(symbols, path + "\\" + "test.txt");
            string password2 = PasswordHasher.GetHash(BaseFileWorker.ReadAll(path + "\\" + "test.txt"));
            Assert.Equal(password, password2);
        }

        [Fact]
        public void TestGetHashFromFile()
        {
            BaseFileWorker.Write("password", path + "\\" + "password.txt");
            BaseFileWorker.Write("salt", path + "\\" + "salt.txt");
            string password = PasswordHasher.GetHash("password", "salt");
            string password2 = PasswordHasher.GetHash(
                BaseFileWorker.ReadAll(path + "\\" + "password.txt"), 
                BaseFileWorker.ReadAll(path + "\\" + "salt.txt")
            );
            Assert.Equal(password, password2);
        }

        [Fact]
        public void TestGetHashEmptyFilename()
        {
            string password = PasswordHasher.GetHash("password", "password");
            BaseFileWorker.Write(password, path + "\\" + string.Empty);
            Assert.NotEqual(password, BaseFileWorker.ReadAll(path + "\\" + string.Empty));
        }

        [Fact]
        public void TestGetHashDifferentExtension()
        {
            string password = PasswordHasher.GetHash("password", "password");
            BaseFileWorker.Write(password, path + "\\" + "test.js");
            Assert.Equal(password, BaseFileWorker.ReadAll(path + "\\" + "test.js"));
        }

        [Fact]
        public void TestGetHashExtensionsOnly()
        {
            string password = PasswordHasher.GetHash("password", "password");
            BaseFileWorker.Write(password, path + "\\" + ".txt");
            Assert.Equal(password, BaseFileWorker.ReadAll(path + "\\" + ".txt"));
        }

        [Fact]
        public void TestGetHashDifferentSalt()
        {
            string password = PasswordHasher.GetHash("password", "salt1");
            string password2 = PasswordHasher.GetHash("password", "salt2");
            BaseFileWorker.Write(password, path + "\\" + "test1.txt");
            BaseFileWorker.Write(password2, path + "\\" + "test2.txt");
            Assert.NotEqual(BaseFileWorker.ReadAll(path + "\\" + "test1.txt"), BaseFileWorker.ReadAll(path + "\\" + "test2.txt"));
        }

        [Fact]
        private void TestInit()
        {
            string password = PasswordHasher.GetHash("password");
            BaseFileWorker.Write(password, path + "\\" + "test1.txt");
            PasswordHasher.Init("salt1", 65531);
            string password2 = PasswordHasher.GetHash("password");
            BaseFileWorker.Write(password2, path + "\\" + "test2.txt");
            Assert.NotEqual(BaseFileWorker.ReadAll(path + "\\" + "test1.txt"), BaseFileWorker.ReadAll(path + "\\" + "test2.txt"));
        }
    }

    public class BinaryFlagTest
    {
        private const string Login = @"sa";
        private const string Password = @"1234";

        private const string Server = @"DESKTOP-BUEC766";
        private const string Database = @"IIG.CoSWE.FlagpoleDB";

        private const bool IsTrusted = true;

        private const int ConnectionTimeout = 15;

        FlagpoleDatabaseUtils flagpoleDB = new FlagpoleDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);

        [Fact]
        public void TestAddFlagTrue()
        {
            MultipleBinaryFlag bFlag = new MultipleBinaryFlag(10);
            string flagView = bFlag.ToString();
            bool flagValue = bFlag.GetFlag();
            Assert.True(flagpoleDB.AddFlag(flagView, flagValue));
        }

        [Fact]
        public void TestAddFlagFalse()
        {
            MultipleBinaryFlag bFlag = new MultipleBinaryFlag(10, false);
            string flagView = bFlag.ToString();
            bool flagValue = bFlag.GetFlag();
            Assert.True(flagpoleDB.AddFlag(flagView, flagValue));
        }

        [Fact]
        public void TestAddFlagMixed()
        {
            MultipleBinaryFlag bFlag = new MultipleBinaryFlag(10, false);
            for (ulong i = 0; i < 10; i += 2) bFlag.SetFlag(i);
            string flagView = bFlag.ToString();
            bool flagValue = bFlag.GetFlag();
            Assert.True(flagpoleDB.AddFlag(flagView, flagValue));
        }

        [Fact]
        public void TestAddFlagManualInputFalse()
        {
            Assert.True(flagpoleDB.AddFlag("TTFFTFTF", false));
        }

        [Fact]
        public void TestAddFlagManualInputTrue()
        {
            Assert.True(flagpoleDB.AddFlag("TTTTTT", true));
        }

        [Fact]
        public void TestAddFlagManualInputBroken()
        {
            Assert.False(flagpoleDB.AddFlag("broken input", true));
        }

        [Fact]
        public void TestGetFlagTrue()
        {
            MultipleBinaryFlag bFlag = new MultipleBinaryFlag(10);
            string flagView = bFlag.ToString();
            bool flagValue = bFlag.GetFlag();
            flagpoleDB.AddFlag(flagView, flagValue);
            string flagViewCheck;
            bool? flagValueCheck;
            int flagId = (int)flagpoleDB.GetIntBySql($"SELECT MultipleBinaryFlagID FROM dbo.MultipleBinaryFlags WHERE MultipleBinaryFlagView = '{flagView}'");
            flagpoleDB.GetFlag(flagId, out flagViewCheck, out flagValueCheck);
            Assert.Equal(flagValue, flagValueCheck);
            Assert.Equal(flagView, flagViewCheck);
        }

        [Fact]
        public void TestGetFlagFalse()
        {
            MultipleBinaryFlag bFlag = new MultipleBinaryFlag(10, false);
            string flagView = bFlag.ToString();
            bool flagValue = bFlag.GetFlag();
            flagpoleDB.AddFlag(flagView, flagValue);
            string flagViewCheck;
            bool? flagValueCheck;
            int flagId = (int)flagpoleDB.GetIntBySql($"SELECT MultipleBinaryFlagID FROM dbo.MultipleBinaryFlags WHERE MultipleBinaryFlagView = '{flagView}'");
            flagpoleDB.GetFlag(flagId, out flagViewCheck, out flagValueCheck);
            Assert.Equal(flagValue, flagValueCheck);
            Assert.Equal(flagView, flagViewCheck);
        }

        [Fact]
        public void TestGetFlagMixed()
        {
            MultipleBinaryFlag bFlag = new MultipleBinaryFlag(10);
            for (ulong i = 0; i < 10; i += 2) bFlag.ResetFlag(i);
            for (ulong i = 0; i < 10; i += 3) bFlag.SetFlag(i);
            string flagView = bFlag.ToString();
            bool flagValue = bFlag.GetFlag();
            flagpoleDB.AddFlag(flagView, flagValue);
            string flagViewCheck;
            bool? flagValueCheck;
            int flagId = (int)flagpoleDB.GetIntBySql($"SELECT MultipleBinaryFlagID FROM dbo.MultipleBinaryFlags WHERE MultipleBinaryFlagView = '{flagView}'");
            flagpoleDB.GetFlag(flagId, out flagViewCheck, out flagValueCheck);
            Assert.Equal(flagValue, flagValueCheck);
            Assert.Equal(flagView, flagViewCheck);
        }

        [Fact]
        public void TestGetFlagLong()
        {
            MultipleBinaryFlag bFlag = new MultipleBinaryFlag(10000);
            string flagView = bFlag.ToString();
            bool flagValue = bFlag.GetFlag();
            flagpoleDB.AddFlag(flagView, flagValue);
            string flagViewCheck;
            bool? flagValueCheck;
            int flagId = (int)flagpoleDB.GetIntBySql($"SELECT MultipleBinaryFlagID FROM dbo.MultipleBinaryFlags WHERE MultipleBinaryFlagView = '{flagView}'");
            flagpoleDB.GetFlag(flagId, out flagViewCheck, out flagValueCheck);
            Assert.Equal(flagValue, flagValueCheck);
            Assert.Equal(flagView, flagViewCheck);
        }
    }
}
