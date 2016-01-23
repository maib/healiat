# **healiat** #

It recovers packer's IAT Redirection.

doesn't recover code redirection or stolen byte.

**it only handles IAT Redirection.**

works well against Themida.

except... sometimes Themida implements its own LoadLibrary and GetProcAddress, and it's actually not an IAT Redirection we should handle.

use ImportREC after running healiat.



**this**

https://b8f247a3-a-62cb3a1a-s-sites.googlegroups.com/site/th3trin/aa/11.PNG?attachauth=ANoY7cov_9DMPxoattheN4bg9tkEKa66dbW-G4Nwwi7dP_3XZ-O1QeHQivA-ZO1NBEF0b3lT8YLkba8hlFN7zljf9L9Vw4wZ8hDRt_8gZF847xzT1Cts9jv_PZsyTaGGh8tRsZrhlVcXbQSUDF_yhe2SRP1xHfuJykDeziDvFf8yhIjTUroMjF-mRlLKvaHvb6g8htSIocCuxH-hb9F9tHNkW8_Yk3fYuw%3D%3D&attredirects=0


**becomes this**

https://b8f247a3-a-62cb3a1a-s-sites.googlegroups.com/site/th3trin/aa/12.PNG?attachauth=ANoY7crcKn0JFJmuN1PifxCyiCqiPC_tKSucMUJDdVxkN-EXqHNXsbP-p3Yr9QSKQUiUhVe55PCy7pAD9P0Tf7akqwHD4PQfUjTegGNdydRTxvO8mzdZGwratUQpS8CBzvoG5oesP1aZCL6_HjB1YtrQpe0b8Un1gwpGwpGIk_v9UIbAFokXoZ6ncgJPVB5MAE2BNc9A1FSKz0-EMZATZxJxxoOWEJ-v3Q%3D%3D&attredirects=0



**and this**

https://b8f247a3-a-62cb3a1a-s-sites.googlegroups.com/site/th3trin/aa/21.PNG?attachauth=ANoY7cqRPwFPvjOAauxkfTugCfq1-qv175YNJjS451_4hUinxei9Db-t8mh9jdtmB-zR8XNy2jT08driVgDkqCyH2WPHA598zzdgFRVM7BYyA-y-4MXCjRBhOqjqkaMe5PtVSX0bL8Rp8cCZ6BujRB6obw-V15ZqmkYbleNlgBYR_TgJsjsiWlC-rjVOn73wKRQEJ1gNDgBeWuiyjLUSMhXDhEJghdtzeA%3D%3D&attredirects=0


**becomes this**

https://b8f247a3-a-62cb3a1a-s-sites.googlegroups.com/site/th3trin/aa/22.PNG?attachauth=ANoY7co4MFQRAbqKz7K3T0t3gD9XwCycSaclnz6lLPg0_98WFaqrO820Vx9ekKcICbmx9C2_npuBsnFanLaHhXekvjbH6e6zVeQfqtf0NWsJRJRu7h9r6nJYeioFANptny3z1kz6JoQH8KAJSc27_aiHSYyG_Gk1YB3v2CS9RJZFIsgxMgrlnd_VdkUjh2NmToWchEQV5C-OGua7pyrPJ1PKSgGNGmKxxg%3D%3D&attredirects=0



needs to be improved in
  1. use cache on xref check for faster operation


pework is from my other project http://code.google.com/p/pework/



have fun.

http://jz.pe.kr