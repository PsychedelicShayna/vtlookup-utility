#include <source/vtlookup.hxx>
#include <openssl/sha.h>

#if defined (WINDOWS) && !defined (UNIX)
#define CONFIG_FILE_PATH "C:/.vtlookup-config.json"
#else
#define CONFIG_FILE_PATH "~/.vtlookup-config.json"
#endif

using HttpResponse = VirusTotalReport::HttpResponse;
using VTERROR = VirusTotalReport::VTERROR;

/* This function uses OpenSSL to calculate the SHA-256 digest of the provided input data
 * and returns a hexadecimal string representation of the digest. */
std::string Sha256Hexdigest(const std::vector<uint8_t>& input_data) {
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest_buffer;

    SHA256_CTX openssl_sha256;
    SHA256_Init(&openssl_sha256);
    SHA256_Update(&openssl_sha256, input_data.data(), input_data.size());
    SHA256_Final(digest_buffer.data(), &openssl_sha256);

    std::stringstream hexdigest_conversion_stream;
    hexdigest_conversion_stream << std::setfill('0') << std::hex;

    for(const auto& byte : digest_buffer) {
        hexdigest_conversion_stream << std::setw(2) << static_cast<uint32_t>(byte);
    }

    return hexdigest_conversion_stream.str();
}

enum struct RESOURCE_TYPE {
    NO_RESOURCE,
    HEXDIGEST,
    FILEPATH
};

int main(int argc, char** argv) {
    std::cout << std::endl;

    std::string virustotal_api_key;
    bool verbose_report = false;

    RESOURCE_TYPE resource_type = RESOURCE_TYPE::NO_RESOURCE;
    std::string target_resource;

    /* This loop handles command line arguments, and configures the above variables
     * using the specified arguments. */

    for(int i=0; i<argc; ++i) {
        const char* current_argument = argv[i];
        const char* next_argument = (i+1) < argc ? argv[i+1] : nullptr;

        // Handle --api-key (-k) argument.
        if((!_stricmp(current_argument, "--api-key") || !_stricmp(current_argument, "-k")) && next_argument != nullptr) {
            virustotal_api_key = std::string(next_argument);
        }

        // Handle --verbose (-v) argument.
        else if(!_stricmp(current_argument, "--verbose") || !_stricmp(current_argument, "-v")) {
            verbose_report = true;
        }

        // Handle --file (-f) argument.
        else if((!_stricmp(current_argument, "--file") || !_stricmp(current_argument, "-f")) && next_argument != nullptr) {
            target_resource = std::string(next_argument);
            resource_type = RESOURCE_TYPE::FILEPATH;
        }

        // Handle --hash (-h) argument.
        else if((!_stricmp(current_argument, "--hash") || !_stricmp(current_argument, "-x")) && next_argument != nullptr) {
            target_resource = std::string(next_argument);
            resource_type = RESOURCE_TYPE::HEXDIGEST;
        }
    }

    // If no API key was specified, attempt to load the API key from the configuration file.
    if(virustotal_api_key.empty()) {
        std::ifstream input_file_stream(CONFIG_FILE_PATH, std::ios::binary);

        if(input_file_stream.good()) {
            std::vector<uint8_t> file_data(
                (std::istreambuf_iterator<char>(input_file_stream)),
                (std::istreambuf_iterator<char>())
            );

            input_file_stream.close();

            Json json_configuration;

            try {
                json_configuration = Json::parse(file_data);
            } catch(const nlohmann::detail::exception&) {
                std::cout << "Encountered a JSON error when attempting to parse the configuration file." << std::endl;
                std::cout << "Please fix the file, or provide an API key through the command line." << std::endl;
                return 1;
            }

            if(json_configuration.find("api_key") != json_configuration.end() && json_configuration.at("api_key").is_string()) {
                const std::string& config_provided_api_key = json_configuration.at("api_key").get<std::string>();

                if(config_provided_api_key.size() == 64) {
                    virustotal_api_key = config_provided_api_key;
                } else {
                    std::cout << "The length of the API key within the configuration file is invalid. Expected 64, got ";
                    std::cout << config_provided_api_key.size() << ". Please correct the error." << std::endl;
                    return 1;
                }
            }
        } else {
            std::cout << "The input stream to the configuration file is bad. A new one will be generated." << std::endl;

            std::ofstream output_file_stream(CONFIG_FILE_PATH, std::ios::binary);

            if(output_file_stream.good()) {
                static Json configuration_file_template {
                    {"api_key", ""}
                };

                const std::string& serialized_template = configuration_file_template.dump(4);

                output_file_stream.write(serialized_template.data(), serialized_template.size());
                output_file_stream.close();

                std::cout << "A new configuration file has been generated, please fill it in and try again." << std::endl;
                return 0;
            } else {
                std::cout << "The output stream to the configuration file is bad. Cannot generate a new configuration file." << std::endl;
                std::cout << "Perhaps this program has been run with insufficient privileges?" << std::endl;
                return 1;
            }
        }
    }

    // If one was specified, but with an invalid length, log the error and exit.
    else if (virustotal_api_key.size() != 64) {
        std::cout << "The length of the provided API key is invalid. Expected 64, got " << virustotal_api_key.size() << ". Please correct the error." << std::endl;
        return 1;
    }

    VirusTotalReport virustotal_report(virustotal_api_key);

    std::string resource_hexdigest;

    switch(resource_type) {
        case RESOURCE_TYPE::FILEPATH : {
            std::ifstream input_file_stream(target_resource, std::ios::binary);
            std::vector<uint8_t> file_data;

            if(input_file_stream.good()) {
                file_data = std::vector<uint8_t>(
                    (std::istreambuf_iterator<char>(input_file_stream)),
                    (std::istreambuf_iterator<char>())
                );

                input_file_stream.close();

                resource_hexdigest = Sha256Hexdigest(file_data);
            } else {
                std::cout << "The input stream to the file resource provided is bad. Please ensure the path is correct, and that this program has sufficient privilages to access it." << std::endl;
                return 1;
            }

            break;
        }

        case RESOURCE_TYPE::HEXDIGEST : {
            resource_hexdigest = target_resource;
            break;
        }

        default : {
            std::cout << "Internal error: unknown resource type " << static_cast<uint32_t>(resource_type) << std::endl;
            return 1;
        }
    }

    HttpResponse http_response;
    VTERROR dl_error_code = virustotal_report.DownloadReport(resource_hexdigest, &http_response);


    // Handle the error code returned by DownloadReport.
    switch(dl_error_code) {
        case VTERROR::ERRORLESS : {
            break;
        }

        case VTERROR::CONNECTION_ERROR : {
            std::cout << "Cannot connect to the VirusTotal API endpoint." << std::endl;
            return 1;
        }

        case VTERROR::INVALID_CURL_HANDLE : {
            std::cout << "The CURL handle created while downloading the report was invalid, cannot continue." << std::endl;
            return 1;
        }

        default : {
            std::cout << "Unhandled error code returned while downloading the report: " << static_cast<uint32_t>(dl_error_code) << std::endl;
            return 1;
        }
    }

    VTERROR ld_error_code = virustotal_report.LoadReport(http_response.Body);
    bool parsed = ld_error_code == VTERROR::PARSING_ERROR ? false : true;

    switch(http_response.StatusCode) {
        case 200 : {
            if(!parsed) {
                std::cout << "The server replied with invalid JSON, cannot parse." << std::endl;
                std::cout << std::string(50, '=') << std::endl;
                std::cout << http_response.Header << std::endl;
                std::cout << std::string(50, '-') << std::endl;
                std::cout << http_response.Body << std::endl;
                return 1;
            }

            switch(virustotal_report.ResponseCode) {
                case -2 : {
                    std::cout << "The resource is still pending an analysis, retry later." << std::endl;
                    return 1;
                }

                case 0 : {
                    std::cout << "The provided resource is not present in the database." << std::endl;

                    if(resource_type == RESOURCE_TYPE::FILEPATH) {
                        std::cout << "Would you like to submit it for an analysis (yes/no) ?~ ";
                        std::string input_string; std::getline(std::cin, input_string);

                        // Ensure the input string is lowercased.
                        for(char& character : input_string)
                            character = (character >= 'A' && character <= 'Z') ? character += 32 : character;

                        if(input_string == "yes" || input_string == "y") {
                            HttpResponse submit_http_response;
                            VTERROR sub_error_code = virustotal_report.SubmitFile(target_resource, &submit_http_response);

                            // Handle the only error code that can come from SubmitFile by returning.
                            if(sub_error_code == VTERROR::INVALID_CURL_HANDLE) {
                                std::cout << "The CURL handle created while submitting the resource was invalid, cannot continue." << std::endl;
                                return 1;
                            }

                            switch(submit_http_response.StatusCode) {
                                case 200 : {
                                    Json sub_body_json;

                                    try {
                                        sub_body_json = Json::parse(submit_http_response.Body);
                                    } catch(nlohmann::detail::exception&) {
                                        std::cout << "Failed to JSON parse the response body returned by the server." << std::endl;
                                        return 1;
                                    }

                                    int32_t response_code = 0x7FFFFFFF;
                                    std::string verbose_msg;

                                    if(sub_body_json.find("response_code") != sub_body_json.end() && sub_body_json.at("response_code").is_number_integer()) {
                                        response_code = sub_body_json.at("response_code").get<int32_t>();
                                    }

                                    if(sub_body_json.find("verbose_msg") != sub_body_json.end() && sub_body_json.at("verbose_msg").is_string()) {
                                        verbose_msg = sub_body_json.at("verbose_msg").get<std::string>();
                                    }

                                    switch(response_code) {
                                        case 1 : {
                                            std::cout << "The resource has been submitted for analysis. Check again later for the results." << std::endl;
                                            return 0;
                                        }

                                        case 0x7FFFFFFF : {
                                            std::cout << "No response code was found in the parsed Json body returned by the server." << std::endl;
                                            std::cout << "Cannot determine the status of the request, exiting.." << std::endl;
                                            return 1;
                                        }

                                        default : {
                                            std::cout << "Unhandled response code: " << response_code << std::endl;
                                            std::cout << "Server message: " << (verbose_msg.empty() ? "None supplied." : verbose_msg) << std::endl;
                                            return 1;
                                        }
                                    }
                                }

                                case 204 : {
                                    std::cout << "VirusTotal API quota reached, please try again later." << std::endl;
                                    return 1;
                                }

                                case -1 : {
                                    std::cout << "HTTP status code is -1, an internal error probably occured." << std::endl;

                                    std::cout << "No status code could be retrieved from the response. Either the response was bad, or the server didn't respond at all" << std::endl;
                                    std::cout << "but the error wasn't properly handled." << std::endl;
                                    return 1;
                                }

                                default : {
                                    std::cout << "Unhandled HTTP response code received: " << http_response.StatusCode << std::endl;
                                    return 1;;
                                }
                            }
                        } else {
                            return 0;
                        }
                    } else {
                        return 0;
                    }
                }

                case 1 : {
                    virustotal_report.RenderReport(verbose_report);
                    return 0;
                }

                case 0x7FFFFFFF : {
                    std::cout << "The VirusTotal API endpoint did not respond with a response code, but responded with HTTP:200/OK." << std::endl;
                    std::cout << "Cannot continue without a response code." << std::endl;
                    std::cout << std::string(50, '=') << std::endl;
                    std::cout << http_response.Header << std::endl;
                    std::cout << std::string(50, '-') << std::endl;
                    std::cout << http_response.Body << std::endl;
                    return 1;
                }
            }

            break;
        }

        case 204 : {
            std::cout << "VirusTotal API quota reached, please try again later." << std::endl;
            return 1;
        };

        case -1 : {
            std::cout << "HTTP status code is -1, an internal error probably occured." << std::endl;

            std::cout << "No status code could be retrieved from the response. Either the response was bad, or the server didn't respond at all" << std::endl;
            std::cout << "but the error wasn't properly handled." << std::endl;
            return 1;
        }

        default : {
            std::cout << "Unhandled HTTP response code received: " << http_response.StatusCode << std::endl;
            return 1;
        }
    }
}
