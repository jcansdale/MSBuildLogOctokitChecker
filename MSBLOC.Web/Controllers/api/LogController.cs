﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using MSBLOC.Core.Interfaces;
using MSBLOC.Web.Attributes;
using MSBLOC.Web.Interfaces;
using MSBLOC.Web.Models;

namespace MSBLOC.Web.Controllers.api
{
    [Authorize]
    [Route("api/[controller]")]
    public class LogController : Controller
    {
        private static readonly FormOptions DefaultFormOptions = new FormOptions();
        private static readonly Lazy<IList<string>> SubmissionDataFormFileNamesLazy = new Lazy<IList<string>>(() =>
        {
            return typeof(SubmissionData).GetProperties()
                .Where(p => p.GetCustomAttributes(typeof(FormFileAttribute), false).Any())
                .Select(p => p.Name)
                .ToList();
        });

        private readonly ILogger<LogController> _logger;
        private readonly ITempFileService _tempFileService;
        private readonly ILogAnalyzerService _logAnalyzerService;

        public LogController(ILogger<LogController> logger, ITempFileService tempFileService, ILogAnalyzerService logAnalyzerService)
        {
            _logger = logger;
            _tempFileService = tempFileService;
            _logAnalyzerService = logAnalyzerService;
        }

        [HttpPost]
        [DisableFormValueModelBinding]
        [MultiPartFormBinding(typeof(SubmissionData))]
        [Route("upload")]
        [Produces("application/json")]
        public async Task<IActionResult> Upload()
        {
            if (!MultipartRequestHelper.IsMultipartContentType(Request.ContentType))
            {
                return BadRequest($"Expected a multipart request, but got {Request.ContentType}");
            }

            // Used to accumulate all the form url encoded key value pairs in the request
            var formAccumulator = new KeyValueAccumulator();

            var boundary = MultipartRequestHelper.GetBoundary(
                MediaTypeHeaderValue.Parse(Request.ContentType),
                DefaultFormOptions.MultipartBoundaryLengthLimit);
            var reader = new MultipartReader(boundary, HttpContext.Request.Body);
            using (_logger.BeginScope(new
            {
                Boundary = boundary,
                Request.ContentType
            }))
            {
                _logger.LogTrace("Reading next section");
                var section = await reader.ReadNextSectionAsync();
                while (section != null)
                {
                    var hasContentDispositionHeader =
                        ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var contentDisposition);

                    if (hasContentDispositionHeader)
                    {
                        _logger.LogTrace("Content Disposition Header: {0}", section.ContentDisposition);

                        if (MultipartRequestHelper.HasFileContentDisposition(contentDisposition))
                        {
                            var fileName = contentDisposition.FileName.Value;

                            if (!SubmissionDataFormFileNamesLazy.Value.Contains(contentDisposition.Name.Value))
                            {
                                _logger.LogInformation($"Unknown file '{contentDisposition.Name.Value}' with fileName: '{fileName}' is being ignored.");
                                // Drains any remaining section body that has not been consumed and
                                // reads the headers for the next section.
                                section = await reader.ReadNextSectionAsync();
                                continue;
                            }

                            formAccumulator.Append(contentDisposition.Name.Value, fileName);

                            var path = await _tempFileService.CreateFromStreamAsync(fileName, section.Body);

                            _logger.LogInformation($"Copied the uploaded file '{fileName}' to path: '{path}'");
                        }
                        else if (MultipartRequestHelper.HasFormDataContentDisposition(contentDisposition))
                        {
                            // Content-Disposition: form-data; name="key"
                            //
                            // value

                            // Do not limit the key name length here because the 
                            // multipart headers length limit is already in effect.
                            var key = HeaderUtilities.RemoveQuotes(contentDisposition.Name);

                            _logger.LogDebug("Retrieving value for {0}", key);

                            var encoding = GetEncoding(section);
                            using (var streamReader = new StreamReader(
                                section.Body,
                                encoding,
                                detectEncodingFromByteOrderMarks: true,
                                bufferSize: 1024,
                                leaveOpen: true))
                            {
                                // The value length limit is enforced by MultipartBodyLengthLimit
                                var value = await streamReader.ReadToEndAsync();
                                if (String.Equals(value, "undefined", StringComparison.OrdinalIgnoreCase))
                                {
                                    value = String.Empty;
                                }

                                formAccumulator.Append(key.Value, value);

                                if (formAccumulator.ValueCount > DefaultFormOptions.ValueCountLimit)
                                {
                                    throw new InvalidDataException(
                                        $"Form key count limit {DefaultFormOptions.ValueCountLimit} exceeded.");
                                }
                            }
                        }
                    }

                    // Drains any remaining section body that has not been consumed and
                    // reads the headers for the next section.
                    section = await reader.ReadNextSectionAsync();
                }
            }

            // Bind form data to a model
            var submissionData = new SubmissionData();

            var bindingSuccessful = await BindDataAsync(submissionData, formAccumulator.GetResults());

            if (!bindingSuccessful)
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
            }

            var requiredFormFileProperties = typeof(SubmissionData).GetProperties()
                .Where(p => p.GetCustomAttributes(typeof(RequiredAttribute), true).Any())
                .Where(p => p.GetCustomAttributes(typeof(FormFileAttribute), true).Any());

            foreach (var requiredFormFileProperty in requiredFormFileProperties)
            {
                var fileName = requiredFormFileProperty.GetValue(submissionData);
                if (!_tempFileService.Files.Contains(fileName))
                {
                    ModelState.AddModelError(requiredFormFileProperty.Name, $"File '{requiredFormFileProperty.Name}' with name: '{fileName}' not found in request.");
                    return BadRequest(ModelState);
                }
            }

            var repositoryOwner = User.Claims.FirstOrDefault(c => c.Type == "urn:msbloc:repositoryOwner")?.Value;
            var repositoryName = User.Claims.FirstOrDefault(c => c.Type == "urn:msbloc:repositoryName")?.Value;

            var checkRun = await _logAnalyzerService.SubmitAsync(
                repositoryOwner,
                repositoryName,
                submissionData.CommitSha,
                submissionData.CloneRoot,
                _tempFileService.GetFilePath(submissionData.BinaryLogFile));

            return Json(checkRun);
        }

        protected virtual async Task<bool> BindDataAsync(SubmissionData model, Dictionary<string, StringValues> dataToBind)
        {
            var formValueProvider = new FormValueProvider(BindingSource.Form, new FormCollection(dataToBind), CultureInfo.CurrentCulture);
            var bindingSuccessful = await TryUpdateModelAsync(model, "", formValueProvider);

            return bindingSuccessful;
        }

        private static Encoding GetEncoding(MultipartSection section)
        {
            var hasMediaTypeHeader = MediaTypeHeaderValue.TryParse(section.ContentType, out var mediaType);
            // UTF-7 is insecure and should not be honored. UTF-8 will succeed in 
            // most cases.
            if (!hasMediaTypeHeader || Encoding.UTF7.Equals(mediaType.Encoding))
            {
                return Encoding.UTF8;
            }
            return mediaType.Encoding;
        }

        private static class MultipartRequestHelper
        {
            public static string GetBoundary(MediaTypeHeaderValue contentType, int lengthLimit)
            {
                var boundary = HeaderUtilities.RemoveQuotes(contentType.Boundary).Value;
                if (string.IsNullOrWhiteSpace(boundary))
                {
                    throw new InvalidDataException("Missing content-type boundary.");
                }

                if (boundary.Length > lengthLimit)
                {
                    throw new InvalidDataException(
                        $"Multipart boundary length limit {lengthLimit} exceeded.");
                }

                return boundary;
            }

            public static bool IsMultipartContentType(string contentType)
            {
                return !string.IsNullOrEmpty(contentType)
                       && contentType.IndexOf("multipart/", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            public static bool HasFormDataContentDisposition(ContentDispositionHeaderValue contentDisposition)
            {
                // Content-Disposition: form-data; name="key";
                return contentDisposition != null
                       && contentDisposition.DispositionType.Equals("form-data")
                       && string.IsNullOrEmpty(contentDisposition.FileName.Value)
                       && string.IsNullOrEmpty(contentDisposition.FileNameStar.Value);
            }

            public static bool HasFileContentDisposition(ContentDispositionHeaderValue contentDisposition)
            {
                // Content-Disposition: form-data; name="myfile1"; filename="Misc 002.jpg"
                return contentDisposition != null
                       && contentDisposition.DispositionType.Equals("form-data")
                       && (!string.IsNullOrEmpty(contentDisposition.FileName.Value)
                           || !string.IsNullOrEmpty(contentDisposition.FileNameStar.Value));
            }
        }

        [HttpGet]
        [Route("test")]
        public IActionResult Test()
        {
            return Json(new
            {
                User.Identity.IsAuthenticated,
                Claims = User.Claims.ToDictionary(c => c.Type, c => c.Value)
            });
        }
    }
}
