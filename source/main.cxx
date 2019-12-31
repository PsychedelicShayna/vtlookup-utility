#include <source/vtlookup.hxx>

int main(int argc, char* argv[]) {
    bool verbose_output = false;    // Enables the verbose output of the VirusTotal report.
    std::string target_hash;        // The hash of the file who's report will be retrieved.
    std::string api_key;            // Api key that will be used to retrieve the report.

    // Loop that handles command line arguments.
    for(int i=0; i<argc; ++i) {
        const char* current_argument = argv[i];
        const char* next_argument = (i+ 1) < argc ? argv[i+1] : nullptr;

        if(!_stricmp(current_argument, "--hash") && next_argument != nullptr) {
            target_hash = std::string(next_argument);
        } else if(!_stricmp(current_argument, "--file") && next_argument != nullptr) {
            std::ifstream file_input_stream(next_argument, std::ios::binary);
            if(file_input_stream.good()) {
                std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(file_input_stream)), (std::istreambuf_iterator<char>()));

                file_input_stream.close();
                // target_hash = Sha256Hexdigest(file_data);
            } else {
                std::cout << "Stream to input file is bad; verify the name and path to the file. Cannot continue without a hash." << std::endl;
                return 2;
            }
        } else if(!_stricmp(current_argument, "--api-key") && next_argument != nullptr) {
            api_key = std::string(next_argument);
        } else if(!_stricmp(current_argument, "--verbose")) {
            verbose_output = true;
        }
    }

    if(api_key.size() == 0) {
        std::ifstream file_input_stream("config.json", std::ios::binary);

        if(file_input_stream.good()) {
            std::vector<char> file_data((std::istreambuf_iterator<char>(file_input_stream)), (std::istreambuf_iterator<char>()));
            std::string file_data_string; file_data_string.resize(file_data.size());
            std::copy(file_data.begin(), file_data.end(), file_data_string.begin());

            Json configuration = Json::parse(file_data_string);

            for(const auto& kvpair : configuration.items()) {
                if(kvpair.key() == "api_key") {
                    api_key = kvpair.value().get<std::string>();
                }
            }
        } else {
            std::cout << "Input stream to configuration file is bad. Cannot continue without an API key." << std::endl;
            std::cout << "Generating a new configuration file.." << std::endl;

            std::ofstream file_output_stream("config.json", std::ios::binary);
            if(file_output_stream.good()) {
                Json configuration_template {{"api_key", ""}};
                std::string configuration_template_string = configuration_template.dump(4);

                file_output_stream.write(configuration_template_string.c_str(), configuration_template_string.size());
                file_output_stream.close();

                std::cout << "Configuration file has been generated. Please fill it in and try again." << std::endl;
                return 1;
            } else {
                std::cout << "Output stream to configuration file is bad. Cannot generate a new configuration file." << std::endl;
                return 3;
            }
        }
    }

    if(api_key.size() != 64) {
        std::cout << "A valid API key has a size of 64. The one supplied has a size of " << api_key.size() << " and is therefore invalid. Cannot continue without an API key." << std::endl;
        return 4;
    }

    if(target_hash.size() == 0) {
        std::cout << "No input hash has been supplied." << std::endl;
        return 5;
    }

    VirusTotalReport virus_total_report(api_key);

    std::string response_body, response_header;
    long status_code = virus_total_report.LoadReport(target_hash, &response_body, &response_header);

    if(status_code != 200) {
        std::cout << std::endl << "The status code returned when attempting to load the report is not okay (should be 200): " << status_code << std::endl;
        std::cout << "Negative codes are internal errors, a code 0 is a connection error, and > 0 are HTTP status codes." << std::endl;

        if(status_code > 0) {
            std::cout << "The response header may yield more information, as the code is an HTTP status code.." << std::endl;
            std::cout << std::string(50, '=') << std::endl;
            std::cout << response_header << std::endl;
            return 1;
        }

    }

    HANDLE console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    uint16_t original_text_attributes;

    CONSOLE_SCREEN_BUFFER_INFO console_screen_buffer_info;
    GetConsoleScreenBufferInfo(console_handle, &console_screen_buffer_info);
    original_text_attributes = console_screen_buffer_info.wAttributes;

    if(virus_total_report.ResponseCode == 1) {
        std::cout << std::endl;
        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << std::string(virus_total_report.ReportLink.size(), '=') << std::endl;
        std::cout << virus_total_report.ReportLink << std::endl;
        std::cout << std::string(virus_total_report.ReportLink.size(), '=') << std::endl;
        std::cout << " -> ";

        SetConsoleTextAttribute(console_handle, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << virus_total_report.Positives;

        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " / ";

        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << virus_total_report.ScanCount;
        std::cout << " [" <<  virus_total_report.DetectionRatio << " %]";
        std::cout << " @ " ;
        std::cout << virus_total_report.ScanDate;
        std::cout << " | ";

        SetConsoleTextAttribute(console_handle, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << virus_total_report.Positives << " positives";

        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " & ";
        std::cout << virus_total_report.Negatives << " negatives";
        std::cout << " out of ";

        SetConsoleTextAttribute(console_handle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << virus_total_report.ScanCount;

        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " distinct antivirus engine scans.." << std::endl;
        std::cout << std::string(virus_total_report.ReportLink.size(), '=') << std::endl;

        SetConsoleTextAttribute(console_handle, original_text_attributes);

        const std::vector<VirusTotalReport::EngineScan>& engine_scans = virus_total_report.EngineScans;

        for(std::size_t i=0; i<engine_scans.size(); ++i) {
            const VirusTotalReport::EngineScan& engine_scan = engine_scans.at(i);
            std::stringstream engine_report_stream;
            engine_report_stream << engine_scan.EngineName << "(" << engine_scan.EngineVersion << ")";
            engine_report_stream << std::string(50 - engine_report_stream.str().size(), '.');
            std::cout << engine_report_stream.str();

            std::string result = (verbose_output ? (engine_scan.Description) : (engine_scan.Detected ? "DIRTY" : "CLEAN"));

            if(result != "CLEAN") {
                SetConsoleTextAttribute(console_handle, FOREGROUND_RED | BACKGROUND_RED | BACKGROUND_BLUE | FOREGROUND_INTENSITY);
            } else {
                SetConsoleTextAttribute(console_handle, FOREGROUND_BLUE | BACKGROUND_BLUE | BACKGROUND_RED | FOREGROUND_INTENSITY);
            }

            std::cout << result;

            SetConsoleTextAttribute(console_handle, original_text_attributes);

            if(verbose_output) {
                std::cout << std::endl;
            } else {
                std::cout << ((i % 2) ? "\n" : " | ");
            }
        }

        std::cout << std::endl << std::string(virus_total_report.ReportLink.size(), '=') << std::endl << std::endl;
    } else {
        std::cout << "The response code is bad. Perhaps an error occured, or the file wasn't submitted yet." << std::endl;
        std::cout << "Response code: " << virus_total_report.ResponseCode << " | Message: " << (virus_total_report.ErrorMessage.empty() ? "None supplied." : virus_total_report.ErrorMessage) << std::endl;
    }

    return 0;
}