export const sendWebhookMessage = async (webhookUrl: string) => {
  const params = {
    username: "Jokz' Tools",
    avatar_url:
      "https://pbs.twimg.com/profile_images/1243255945913872384/jOxyDffX_400x400.jpg",
    embeds: [
      {
        title: "Astral Logs",
        author: {
          name: "Astral",
        },

        footer: {
          icon_url:
            "https://pbs.twimg.com/profile_images/1243255945913872384/jOxyDffX_400x400.jpg",
          text: "Embed Sender | @JokzTools",
        },
        color: 0xff0000,
        timestamp: new Date(),
      },
    ],
  };
  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(params),
  });

  const data = await response.json();

  console.log(data);

  if (!response.ok) throw new Error("Error to send a discord log");
};
