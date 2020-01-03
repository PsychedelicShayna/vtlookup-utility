#include <source/vtlookup.hxx>
#include <openssl/sha.h>

#include <conio.h>

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
    bool display_detection_flags = false;

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

        // Handle --detection-flags (-v) argument.
        else if(!_stricmp(current_argument, "--detection-flags") || !_stricmp(current_argument, "-v")) {
            display_detection_flags = true;
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
        std::ifstream input_file_stream("config.json", std::ios::binary);

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

            std::ofstream output_file_stream("config.json", std::ios::binary);

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

    VirusTotalReport::HttpResponse http_response;
    Json resource_report_json;

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
            } else {
                std::cout << "The input stream to the file resource provided is bad. Please ensure the path is correct, and that this program has sufficient privilages to access it." << std::endl;
                return 1;
            }

            const std::string& file_hexdigest = Sha256Hexdigest(file_data);

            const std::pair<VTERROR, VTERROR>& error_codes =
                virustotal_report.DownloadAndLoadReport(file_hexdigest, &resource_report_json, &http_response);

            if(error_codes.first == VTERROR::ERRORLESS && error_codes.second == VTERROR::ERRORLESS) {
                if(http_response.StatusCode == 200) {
                    switch(virustotal_report.ResponseCode) {
                        case 0 : {
                            std::cout << virustotal_report.ErrorMessage << std::endl;
                            std::cout << "Would you like to submit the file for analysis Y/N? ";

                            uint32_t pressed_char = _getch();
                            for(;pressed_char != 'y' && pressed_char != 'n'; pressed_char = _getch());

                            std::cout << std::endl;

                            if(pressed_char == 'y') {
                                VirusTotalReport::HttpResponse submit_file_http_response;
                                Json submission_status_json;

                                virustotal_report.SubmitFile(target_resource, &submission_status_json, &submit_file_http_response);

                                if(submit_file_http_response.StatusCode == 200) {
                                    if(submission_status_json.find("verbose_msg") != submission_status_json.end() && submission_status_json.at("verbose_msg").is_string()) {
                                        std::cout << submission_status_json.at("verbose_msg").get<std::string>();
                                        std::cout << std::endl;
                                        return 0;
                                    } else {
                                        std::cout << "No message received from server, this could be indicative of a problem." << std::endl;
                                        std::cout << "Submission status unknown." << std::endl << std::endl;
                                        return 1;
                                    }
                                } else {
                                    std::cout << "Bad HTTP status code: " << submit_file_http_response.StatusCode << std::endl;
                                    std::cout << "Perhaps the header and body may reveal more information." << std::endl << std::endl;

                                    std::cout << std::string(50, '=');
                                    std::cout << submit_file_http_response.Header << std::endl;
                                    std::cout << std::string(50, '-');
                                    std::cout << submit_file_http_response.Body << std::endl;
                                    std::cout << std::string(50, '-') << std::endl << std::endl;
                                    return 1;
                                }

                            } else {
                                std::cout << "Nothing to do, exiting.." << std::endl << std::endl;
                                return 1;
                            }

                            break;
                        }

                        case 1 : {
                            virustotal_report.RenderReport(!display_detection_flags);
                            return 0;
                            break;
                        }

                        case -2:  {
                            std::cout << virustotal_report.ErrorMessage << std::endl;
                            break;
                        }

                        default : {
                            std::cout << "Unknown response code " << virustotal_report.ResponseCode << std::endl;
                            break;
                        }
                    }
                } else if(http_response.StatusCode == 204) {
                    std::cout << "VirusTotal API quota has been reached, please wait a moment and try again." << std::endl;
                    return 1;
                } else {
                    std::cout << "Bad HTTP status code: " << http_response.StatusCode << std::endl;
                    std::cout << "Perhaps the header and body may reveal more information." << std::endl << std::endl;

                    std::cout << std::string(50, '=');
                    std::cout << http_response.Header << std::endl;
                    std::cout << std::string(50, '-');
                    std::cout << http_response.Body << std::endl;
                    std::cout << std::string(50, '-');
                    return 1;
                }
            } else {
                std::cout << "Internal error code D" << static_cast<uint32_t>(error_codes.first) << " L" << static_cast<uint32_t>(error_codes.second) << std::endl;
                return 1;
            }

            break;
        }

        case RESOURCE_TYPE::HEXDIGEST : {
            const std::pair<VTERROR, VTERROR>& error_codes =
                virustotal_report.DownloadAndLoadReport(target_resource, &resource_report_json, &http_response);

            if(error_codes.first == VTERROR::ERRORLESS && error_codes.second == VTERROR::ERRORLESS) {
                if(http_response.StatusCode == 200) {
                    switch(virustotal_report.ResponseCode) {
                        case 0 : {
                            std::cout << virustotal_report.ErrorMessage << std::endl;
                            std::cout << "Please provide the original file if you want to have it analyzed." << std::endl;
                            return 1;
                        }

                        case 1 : {
                            virustotal_report.RenderReport(!display_detection_flags);
                            return 0;
                        }
                    }
                } else if(http_response.StatusCode == 204) {
                    std::cout << "VirusTotal API quota has been reached, please wait a moment and try again." << std::endl;
                    return 1;
                } else {
                    std::cout << "Bad HTTP status code: " << http_response.StatusCode << std::endl;
                    std::cout << "Perhaps the header and body may reveal more information." << std::endl << std::endl;

                    std::cout << std::string(50, '=');
                    std::cout << http_response.Header << std::endl;
                    std::cout << std::string(50, '-');
                    std::cout << http_response.Body << std::endl;
                    std::cout << std::string(50, '-');
                    return 1;
                }
            }

            break;
        }

        case RESOURCE_TYPE::NO_RESOURCE : {
            std::cout << "You have not provided a resource. You may provide a file through the --file(-f) argument, or a hash through the --hash(-x) argument." << std::endl;
            return 1;
        }
    }
}
