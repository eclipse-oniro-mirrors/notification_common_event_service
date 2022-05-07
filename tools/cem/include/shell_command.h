/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BASE_NOTIFICATION_CES_STANDARD_CESFWK_TOOLS_CEM_INCLUDE_SHELL_COMMAND_H
#define BASE_NOTIFICATION_CES_STANDARD_CESFWK_TOOLS_CEM_INCLUDE_SHELL_COMMAND_H

#include <map>
#include <string>
#include <functional>
#include <vector>

#include "utils/native/base/include/errors.h"

namespace OHOS {
namespace EventFwk {
namespace {
const std::string HELP_MSG_NO_OPTION = "error: you must specify an option at least.";
}  // namespace

class ShellCommand {
public:
    /**
     * Constructor.
     *
     * @param argc Indicates the argument count.
     * @param argv Indicates the argument values.
     * @param name Indicates the tool name.
     */
    ShellCommand(int argc, char *argv[], std::string name);

    virtual ~ShellCommand();

    /**
     * Processes the command.
     *
     * @return Returns result code.
     */
    ErrCode OnCommand();

    /**
     * Executes the command.
     *
     * @return Returns result.
     */
    std::string ExecCommand();

    /**
     * Gets the error message of the command.
     *
     * @return Returns the error message of the command.
     */
    std::string GetCommandErrorMsg() const;

    /**
     * Gets the error message of the unknown option.
     *
     * @param unknownOption Indicates the unknown option.
     * @return Returns the unknown option.
     */
    std::string GetUnknownOptionMsg(std::string &unknownOption) const;

    /**
     * Gets the message from the code.
     *
     * @param code Indicates the code.
     * @return Returns the message from the code.
     */
    std::string GetMessageFromCode(int32_t code) const;

    /**
     * Creates the command map.
     *
     * @return Returns result code.
     */
    virtual ErrCode CreateCommandMap() = 0;

    /**
     * Creates the message map.
     *
     * @return Returns result code.
     */
    virtual ErrCode CreateMessageMap() = 0;

    /**
     * Inits.
     *
     * @return Returns result code.
     */
    virtual ErrCode init() = 0;

protected:
    static constexpr int MIN_ARGUMENT_NUMBER = 2;

    int argc_;
    char **argv_;

    std::string cmd_;
    std::vector<std::string> argList_;

    std::string name_;
    std::map<std::string, std::function<int()>> commandMap_;
    std::map<int32_t, std::string> messageMap_;

    std::string resultReceiver_ = "";
};
}  // namespace EventFwk
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_CES_STANDARD_CESFWK_TOOLS_CEM_INCLUDE_SHELL_COMMAND_H