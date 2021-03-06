﻿using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace MSBLOC.Web.Tests
{
    public class ProgramTests
    {
        [Fact]
        public void ConfigureAppConfigurationAzureTest()
        {
            var context = Substitute.For<WebHostBuilderContext>();
            
            var baseConfigRoot = Substitute.For<IConfigurationRoot>();
            baseConfigRoot["Azure:KeyVault"].Returns("NameOfVault");

            var config = Substitute.For<IConfigurationBuilder>();
            config.Add(Arg.Do<EnvironmentVariablesConfigurationSource>(arg =>
            {
                arg.Prefix.Should().Be("MSBLOC_");
            }));
            config.Build().Returns(baseConfigRoot);

            var keyVaultClient = Substitute.For<KeyVaultClient>();

            var keyVaultConfigRoot = Substitute.For<IConfigurationRoot>();

            var configurationBuilder = Substitute.For<IConfigurationBuilder>();
            configurationBuilder.Build().Returns(keyVaultConfigRoot);
            configurationBuilder.Add(Arg.Do<ChainedConfigurationSource>(arg =>
            {
                arg.Configuration.Should().Be(keyVaultConfigRoot);
            }));

            var program = new ProgramStub
            {
                KeyVaultClient = keyVaultClient,
                ConfigurationBuilder = configurationBuilder
            };

            program.MSBLOCConfigureAppConfiguration(context, config);

            config.Received().Add(Arg.Any<EnvironmentVariablesConfigurationSource>());
            config.Received().Build();

            configurationBuilder.Received().Add(Arg.Any<IConfigurationSource>());
            configurationBuilder.Received().Build();

            config.Received().Add(Arg.Any<ChainedConfigurationSource>());
        }

        [Fact]
        public void ConfigureAppConfigurationNotAzureTest()
        {
            var context = Substitute.For<WebHostBuilderContext>();

            var configRoot = Substitute.For<IConfigurationRoot>();
            configRoot["Azure:KeyVault"].Returns((string) null);

            var config = Substitute.For<IConfigurationBuilder>();
            config.Add(Arg.Do<EnvironmentVariablesConfigurationSource>(arg =>
            {
                arg.Prefix.Should().Be("MSBLOC_");
            }));
            config.Build().Returns(configRoot);

            new ProgramStub().MSBLOCConfigureAppConfiguration(context, config);

            config.Received().Add(Arg.Any<EnvironmentVariablesConfigurationSource>());
            config.Received().Build();
        }

        public class ProgramStub : Program
        {
            public KeyVaultClient KeyVaultClient { get; set; }
            public IConfigurationBuilder ConfigurationBuilder { get; set; }

            protected override KeyVaultClient GetKeyVaultClient()
            {
                return KeyVaultClient;
            }

            protected override IConfigurationBuilder GetConfigurationBuilder()
            {
                return ConfigurationBuilder;
            }
        }
    }
}
