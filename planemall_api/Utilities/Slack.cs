using SlackBotMessages.Models;
using SlackBotMessages;

namespace planemall_api.Utilities
{
    public static class Slack
    {
        #region Properties

        public enum Enum_Bot_Type
        {
            telegram_login
        }

        #endregion


        #region Functions

        public async static Task<bool> SendSlackMessageAsync(Enum_Bot_Type bot_type, string message, ILogger<object> _logger, string emoji = null)
        {
            bool ret = true;

            try
            {
                #region Request Elaboration

                SbmClient slack_bot_client = null;

                if (!string.IsNullOrEmpty(emoji))
                    emoji = $":{emoji}:";

                Message mex = new Message()
                {
                    Text = message,
                    IconEmoji = emoji
                };

                switch (bot_type)
                {
                    case Enum_Bot_Type.telegram_login:

                        slack_bot_client = new SbmClient("https://hooks.slack.com/services/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");
                        mex.Username = "Telegram Login Bot";

                        break;
                }

                if (slack_bot_client is not null)
                {
                    if (!System.Diagnostics.Debugger.IsAttached)
                    {
                        await slack_bot_client.SendAsync(mex);
                    }
                }

                #endregion
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in SendSlackMessageAsync(); error details: {ex.Message}");
                ret = false;
            }

            return ret;
        }

        #endregion
    }
}
