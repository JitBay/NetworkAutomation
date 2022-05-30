import threading

from importlib_metadata import entry_points
from netmiko import ConnectHandler, Netmiko
import time
from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
import os
from functools import partial
import tkinter.font
import csv
from csv import writer
import ipaddress
from datetime import datetime
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import glob
from tkinter import filedialog
from netmiko.ssh_exception import NetMikoTimeoutException
from paramiko.ssh_exception import SSHException
from netmiko.ssh_exception import AuthenticationException
from napalm import get_network_driver


#1-------------------------------------------------------------------------------
def password_change():
    pwd_chng_window = Toplevel(root)
    new_password = StringVar()
    pwd_chng_window.title('Encryption password')
    xpos = 10
    ypos = 600
    wgeo = '300x200+' + str(xpos) + '+' + str(ypos)
    pwd_chng_window.geometry(wgeo)
    pwd_chng_window.configure(background='Grey')
    pwd_chng_window.resizable(False, False)
    pwd_chng_window.grab_set()
    Label(pwd_chng_window, text='New Password', font='Arial 15 bold ',bg='Grey').pack(side=TOP, pady=5)
    new_password_entry = Entry(pwd_chng_window, textvariable=new_password, show="*",
    width=30, font='Helvetica 11')
    new_password_entry.pack(side=TOP, pady=5)
    new_password_entry.focus()
    pwd_chng_ok_btn = Button(pwd_chng_window, text=" OK ", width=15,
    height=1,
    font='Arial 15 bold', command=pwd_chng_window.destroy)
    pwd_chng_ok_btn.pack(side=BOTTOM, pady=15)
    pwd_chng_window.attributes('-topmost', 1) # Raising root aboveall other windows
    root.wait_window(pwd_chng_window)
    dec_key = create_key()
    cipher = Fernet(dec_key) 
    enc_key = get_key(new_password.get()).decode()
    enc_cipher = Fernet(enc_key)
    new_pass_rows = [['IP', 'Password', 'Type', 'Description','ssh_username', 'ssh_password']]
    with open('./Devices.csv', 'rt') as csv_f:
        reader = csv.reader(csv_f, delimiter=',')
        for row in reader:
            if row[1] != 'Password':
                enable_to_dec = row[1]
                ssh_to_dec = row[5]
                dec_enable = cipher.decrypt(enable_to_dec.encode()).decode()
                dec_ssh = cipher.decrypt(ssh_to_dec.encode()).decode()
                row[1] = enc_cipher.encrypt(dec_enable.encode()).decod()
                row[5] = enc_cipher.encrypt(dec_ssh.encode()).decode()
                new_pass_rows.append(row)

    with open('./Devices.csv', 'w', newline='') as csv_w:
        new_pass_writer = csv.writer(csv_w, delimiter=',')
        for device_row in new_pass_rows:
            new_pass_writer.writerow(device_row)

    messagebox.showinfo('Success', 'Password changed successfully!')



def ip_entered(ip):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        messagebox.showerror('Error', 'Pleas enter a valid IP \n' +'IP format should be xxx.xxx.xxx.xxx')
        return 0


def get_key(master_pwd):
    key_salt = b'(\n\xec\xd9\x1a\xcc\x1e\x86=\xa8\x1b\xd3G\xb9P\xb5'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32,salt=key_salt, iterations=100000, backend=default_backend())
    enc_key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
    return enc_key




def get_config_name(selected_value):
    if automations_list.get(automations_list.curselection()) =='Backup Configuration':
       for child in automation_conf_frame.winfo_children():
            if str(child) != '.!labelframe2.!button':
                child.pack_forget()
            backup_name_lbl.pack(side=TOP, pady=20)
            automation_filter_frame.pack(side=TOP)
            cbtn_date_ip.pack(side=TOP, anchor='w')
            cbtn_ip_date.pack(side=TOP, anchor='w')
            cbtn_manual.pack(side=TOP, anchor='w')

    elif automations_list.get(automations_list.curselection()) == 'Restore Configuration':
        for child in automation_conf_frame.winfo_children():
            if str(child) != '.!labelframe2.!button':
                child.pack_forget()
            restore_name_lbl.pack(side=TOP, pady=20)
            automation_restore_options_frame.pack(side=TOP)
            cbtn_last.pack(side=TOP, anchor='w')
            cbtn_manual_ask.pack(side=TOP, anchor='w')
    elif automations_list.get(automations_list.curselection()) == 'Enable OSPF':
        device_to_enable = [device_list.get(sel_ip) for sel_ip in list(device_list.curselection())]
        if len(device_to_enable) == 0:
            messagebox.showwarning('Alert', 'Select first the devices you want \n to enable OSPF')
            automations_list.selection_clear(0, 'end')
        else:
            for child in automation_conf_frame.winfo_children():
                if str(child) != '.!labelframe2.!button':
                    child.pack_forget()
            for child in ospf_main_frm.winfo_children():
                child.pack_forget()
            for child in ospf_device_frm.winfo_children():
                child.pack_forget()
            for child in ospf_process_id_frm.winfo_children():
                child.pack_forget()
            for child in ospf_ip_frm.winfo_children():
                child.pack_forget()
            for child in ospf_mask_frm.winfo_children():
                child.pack_forget()
            for child in ospf_area_id_frm.winfo_children():
                child.pack_forget()
            full_list = [device_list.get(sel_ip) for sel_ip in list(device_list.curselection())]
            name_list= []
             
            for backup_dev in full_list:
                name_list.append(backup_dev[1])
                ospf_main_frm.pack(side=TOP)
                ospf_device_frm.pack(side=LEFT, anchor='n')
                ospf_process_id_frm.pack(side=LEFT, anchor='n')
                ospf_ip_frm.pack(side=LEFT, anchor='n')
                ospf_mask_frm.pack(side=LEFT, anchor='n')
                ospf_area_id_frm.pack(side=LEFT, anchor='n')
                ospf_device_lbl.pack(side=TOP)
                ospf_process_id_lbl.pack(side=TOP)
                ospf_ip_lbl.pack(side=TOP)
                ospf_mask_lbl.pack(side=TOP)
                ospf_area_id_lbl.pack(side=TOP)
                global entry
                entry ={}
                for i, n in enumerate(name_list):
                    ospf_device_name = str(name_list[i])
                    Label(ospf_device_frm, text=ospf_device_name,font=('Aria', 9), fg='black', width=15, anchor='w',bg='white').pack(side=TOP, pady=5)
                    ospf_pid = Entry(ospf_process_id_frm, width=10,font='Helvetica 11')
                    ospf_pid.pack(side=TOP, pady=5)
                    ospf_ip = Entry(ospf_ip_frm, width=25, font='Helvetica11')
                    ospf_ip.pack(side=TOP, pady=5)
                    ospf_mask = Entry(ospf_mask_frm, width=25, font='Helvetica 11')
                    ospf_mask.pack(side=TOP, pady=5)
                    ospf_area = Entry(ospf_area_id_frm, width=10,font='Helvetica 11')
                    ospf_area.pack(side=TOP, pady=5)
                    entry[n] = [ospf_pid, ospf_ip, ospf_mask, ospf_area]
        
    elif automations_list.get(automations_list.curselection()) == 'AddFirewall Rule':
        for child in automation_conf_frame.winfo_children():
            if str(child) != '.!labelframe2.!button':
                child.pack_forget()
            acl_number_frm.pack(side=LEFT, padx=5, pady=10)
            acl_type_frm.pack(side=LEFT, padx=5, pady=10)
            acl_options_frm.pack(side=LEFT, padx=5, pady=10)
            acl_source_frm.pack(side=LEFT, padx=5, pady=10)
            acl_swildcard_frm.pack(side=LEFT, padx=5, pady=10)
            acl_des_frm.pack(side=LEFT, padx=5, pady=10)
            acl_dwildcard_frm.pack(side=LEFT, padx=5, pady=10)
            acl_number_lbl.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_type_lbl.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_protocol_lbl.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_source_lbl.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_swildcard_lbl.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_des_lbl.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_dwildcard_lbl.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_nmb_entry.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_types.pack(side=TOP, anchor='n', padx=5, pady=10)
            acl_options.pack(side=TOP, anchor='n', padx=5, pady=10)
            source_ip_entry.pack(side=TOP, anchor='n', padx=5, pady=10)
            source_wildcard_entry.pack(side=TOP, anchor='n', padx=5,pady=10)
            destination_ip_entry.pack(side=TOP, anchor='n', padx=5,pady=10)
            destination_wildcard_entry.pack(side=TOP, anchor='n', padx=5,pady=10)


def create_key():
    pwd_window = Toplevel(root)
    master_password = StringVar()
    pwd_window.title('Encryption password')
    xpos = 10
    ypos = 600
    wgeo = '300x200+' + str(xpos) + '+' + str(ypos)
    pwd_window.geometry(wgeo)
    pwd_window.configure(background='Grey')
    pwd_window.resizable(False, False)
    pwd_window.grab_set()
    Label(pwd_window, text='Please enter Master Password', font='Arial 15 bold ', bg='Grey').pack(side=TOP, pady=5)
    master_password_entry = Entry(pwd_window, textvariable=master_password, show="*",width=30, font='Helvetica 11')
    master_password_entry.pack(side=TOP, pady=5)
    master_password_entry.focus()
    pwd_ok_btn = Button(pwd_window, text=" OK ", width=15, height=1,font='Arial 15 bold', command=pwd_window.destroy)
    pwd_ok_btn.pack(side=BOTTOM, pady=15)
    pwd_window.attributes('-topmost', 1)
    root.wait_window(pwd_window)
    decryption_pwd = master_password.get()
    ret_dec_key = get_key(decryption_pwd).decode()
    return ret_dec_key


def backup_config(host, path):
    output_description.insert(END, f'connecting and getting configuration from:{host["host"]}\n')
    output_description.update_idletasks()
    try:
        netmiko_connection = Netmiko(**host)
    except NetMikoTimeoutException:
        messagebox.showerror('Error', ('Timeout error to: ' +host["host"]))

    except AuthenticationException:
        messagebox.showerror('Error', 'Authentication failure errorto: ' + host["host"])
    
    except SSHException:
        messagebox.showerror('Error', 'SSH Error. Check if SSH is enabled ' + host["host"])
    
    except EOFError:
        messagebox.showerror('Error', 'End of file while attempting device' + host["host"])

    except Exception as unknown_error:
        messagebox.showerror('Error', 'Unknown error to: ' + host["host"] + str(unknown_error))

    netmiko_connection.enable()
    output = netmiko_connection.send_command('show run')
    output = output[output.find('version'):]
    output = output.rsplit("end", 1)[0]

    with open(path, "w") as text_file:
        text_file.write(output)
    
    output_description.insert(END, '\n' + ('-' * (len(path) + 50)) +'\n')

    output_description.insert(END, 'Configuration backup successfully saved at : ' + path)

    output_description.insert(END, '\n' + ('-' * (len(path) + 50)) + '\n')

    output_description.update_idletasks()
    netmiko_connection.disconnect()


def restore_config(r_host, r_filename):
    s1 = time.time()
    output_description.insert(END, f'Restoring configuration at:{r_host["ip"]}\n')
    output_description.update_idletasks()
    net_connection = ConnectHandler(**r_host)
    output_description.insert(END, f'connecting to:{r_host["ip"]}\n')
    output_description.update_idletasks()
    net_connection.send_config_set(r_filename, cmd_verify=False)
    output_description.insert(END, 'Configuration successfully restored from : ' + r_filename)
    output_description.insert(END,'\n-----------------------------------------------------------------------\n')
    output_description.update_idletasks()
    net_connection.send_command('wr')
    net_connection.disconnect()
    e1 = time.time()
    print('res fun :', e1 - s1)

def ospf_config(host, pid, ip_for_ospf, mask_for_ospf, area):
    output_description.insert(END, f'connecting and enabling OSPF on:{host["ip"]}\n')
    output_description.update_idletasks()
    #try:
    ospf_connection = Netmiko(**host)
   # except NetMikoTimeoutException:
    #    messagebox.showerror('Error', ('Timeout error to: ' + host["ip"]))
   # except AuthenticationException:
     #   messagebox.showerror('Error', 'Authentication failure error to: ' + host["ip"])
   # except SSHException:
      #  messagebox.showerror('Error', 'SSH Error. Check if SSH is enabled ' + host["ip"])
   # except EOFError:
       # messagebox.showerror('Error', 'End of file while attempting device' + host["ip"])
   # except Exception as unknown_error:
       # messagebox.showerror('Error', 'Unknown error to: ' + host["ip"] + str(unknown_error))
        
    ospf_connection.enable()
    ospf_commands = ['enable', 'configure terminal', 'router ospf ' + pid, 'network ' + ip_for_ospf + ' ' + mask_for_ospf + ' area ' + area, 'end']
    output = ospf_connection.send_config_set(ospf_commands)
    print(output)
    output_description.insert(END, '\n' + ('-' * (len(ip_for_ospf) + 50)) + '\n')
    output_description.insert(END, 'OSPF enabled at : ' + host["ip"] + ' for ' + ip_for_ospf + ' network')
    output_description.insert(END, '\n' + ('-' * (len(ip_for_ospf) + 50)) + '\n')
    output_description.update_idletasks()
    ospf_connection.disconnect()


def acl_config(ac_host, ac_num, ac_action, ac_prot, ac_sip, ac_sw,ac_dip, ac_dw):
    output_description.insert(END, f'connecting and configuring ACL on:{ac_host["ip"]}\n')
    output_description.update_idletasks()
        # try:
    acl_connection = Netmiko(**ac_host)
    acl_connection.enable()
    acl_commands = ['access-list ' + ac_num + ' ' + ac_action + ' ' + ac_prot + ' ' + ac_sip + ' ' + ac_sw + ' ' + ac_dip + ' ' + ac_dw ]
    output = acl_connection.send_config_set(acl_commands)
    output_description.insert(END, '\n' + ('-' * 50) + '\n')
    output_description.insert(END, 'ACL enabled on : ' + ac_host["ip"])
    output_description.insert(END, '\n' + ('-' * 50) + '\n')
    output_description.update_idletasks()
    acl_connection.disconnect()
    print(output)


def execute_automations():
    output_description.delete('1.0', END)
    if automations_list.get(automations_list.curselection()) == 'Backup Configuration':
        if c_date_ip.get() == 1 or c_ip_date.get() == 1 or c_manual.get() == 1:
            if c_manual.get() == 1 and manual_config_name.get() == '':
                messagebox.showerror('Error', 'Filename can not be empty')
            else:
                device_to_backup = [device_list.get(sel_ip) for sel_ip in list(device_list.curselection())]
                device_to_backup_ip = []
                for backup_dev in device_to_backup:
                    device_to_backup_ip.append(backup_dev[1])
                dec_key = create_key()
                cipher = Fernet(dec_key)
                thread_list = list()
                for dev_ip in device_to_backup_ip:
                    with open('./Devices.csv', 'rt') as csv_f:
                        reader = csv.reader(csv_f, delimiter=',')
                        for row in reader:
                            if row[0] == dev_ip:
                                pwd_to_dec = row[5]
                    netmiko_host = {'host': dev_ip, 'port': '22','username': 'ihu', 'password':cipher.decrypt(pwd_to_dec.encode()).decode(), 'device_type': 'cisco_ios','fast_cli': False}
                    b_working_folder = os.getcwd()
                    if c_date_ip.get() == 1:
                        if not os.path.exists(b_working_folder +'\\Config\\backup_files\\' + netmiko_host['host']):
                            os.makedirs(b_working_folder + '\\Config\\backup_files\\' + netmiko_host['host'])
                        backup_filename = str(b_working_folder + '\\Config\\backup_files\\' + netmiko_host['host'] + '\\' + datetime.now().strftime('%d_%m_%Y_%H_%M_%S') + '_' + 'backup_of_' + netmiko_host['host'] + '.txt')
                    elif c_ip_date.get() == 1:
                        if not os.path.exists(b_working_folder + '\\Config\\backup_files\\' + netmiko_host['host']):
                            os.makedirs(b_working_folder + '\\Config\\backup_files\\' + netmiko_host['host'])
                        backup_filename = str(b_working_folder + '\\Config\\backup_files\\' + netmiko_host['host'] + '\\' + netmiko_host['host'] + '_' + 'backup_of_' + datetime.now().strftime('%d_%m_%Y_%H_%M_%S') + '.txt')
                    
                    else:
                        if not os.path.exists(b_working_folder + '\\Config\\backup_files\\' + netmiko_host['host']): 
                            os.makedirs(b_working_folder + '\\Config\\backup_files\\' + netmiko_host['host'])
                        backup_filename = str(b_working_folder + '\\Config\\backup_files\\' + netmiko_host['host'] + '\\' + netmiko_host['host'] + '_' + manual_config_name.get() + '.txt')

                    thread_item = threading.Thread(target=backup_config, args=(netmiko_host, backup_filename,))
                    thread_list.append(thread_item)
                for th in thread_list:
                    th.start()
        else:
            messagebox.showerror('Error', 'Select on of the below options\n Date First\n IP First\n Manual')
            manual_entry.delete(0, 'end')




    elif automations_list.get(automations_list.curselection()) == 'Restore Configuration':
        start = time.time()
        if c_last.get() == 1 or c_manual_ask.get() == 1:
            device_to_backup = [device_list.get(sel_ip) for sel_ip in list(device_list.curselection())]
            device_to_backup_ip = []
            for backup_dev in device_to_backup:
                device_to_backup_ip.append(backup_dev[1])
            dec_key = create_key()
            cipher = Fernet(dec_key)
            thread_list = list()
            for dev_ip in device_to_backup_ip:
                with open('./Devices.csv', 'rt') as csv_f:
                    reader = csv.reader(csv_f, delimiter=',')
                    for row in reader:
                        if row[0] == dev_ip:
                            pwd_to_dec = row[5]
                device_args = {'device_type': 'cisco_ios', 'ip': dev_ip, 'username': 'ihu', 'password': cipher.decrypt(pwd_to_dec.encode()).decode(), 'port': 22, 'verbose': True,'global_delay_factor': 2} 
                working_folder = os.getcwd()
                if c_last.get() == 1:
                    device_folder = glob.glob(working_folder + '\\Config\\backup_files\\' + device_args['ip'] + '\\*')
                    restore_filename = max(device_folder,key=os.path.getctime)  
                else:
                    messagebox.showinfo('Select file', 'Select the configuration file to restore for ' + device_args["ip"])
                    restore_filename = filedialog.askopenfilename()
                
                thread_item = threading.Thread(target=restore_config,args=(device_args, restore_filename,))
                thread_list.append(thread_item)

            for th in thread_list:
                th.start()

        else:
            messagebox.showerror('Error', 'Select on of the below options\n ''Restore most recent backup\n Manual restore')
        end = time.time()
        print('all =', end - start)




    elif automations_list.get(automations_list.curselection()) == 'Enable OSPF':
        device_to_enable = [device_list.get(sel_ip) for sel_ip in list(device_list.curselection())]
        device_to_enable_ip = []
        for backup_dev in device_to_enable:
            device_to_enable_ip.append(backup_dev[1])
        dec_key = create_key()
        cipher = Fernet(dec_key)
        thread_list = []
        for dev_ip in device_to_enable_ip:
            with open('./Config/Devices.csv', 'rt') as csv_f:
                reader = csv.reader(csv_f, delimiter=',')
                for row in reader:
                    if row[0] == dev_ip:
                        pwd_to_dec = row[5]
                        dev_type = row[2]
            ospf_device_args = {'device_type': 'cisco_ios', 'ip': dev_ip, 'username': 'ihu', 'password': cipher.decrypt(pwd_to_dec.encode()).decode(), 'port': 22, 'verbose': True,'global_delay_factor': 2}            
            if (len(entry[dev_ip][0].get()) == 0 or len(entry[dev_ip][1].get()) == 0 or len(entry[dev_ip][2].get()) == 0 or len(entry[dev_ip][3].get()) == 0):
                messagebox.showwarning('Alert', 'All OSPF parameters should be filled')
            elif dev_type == 'Switch':
                messagebox.showwarning('Alert', 'OSPF can be enabled only in routers \n Nothing changed on'' device with IP' + dev_ip)
            else:
                ospf_pid = entry[dev_ip][0].get()
                ospf_ip = entry[dev_ip][1].get()
                ospf_mask = entry[dev_ip][2].get()
                ospf_area = entry[dev_ip][3].get()   
                thread_item = threading.Thread(target=ospf_config,args=(ospf_device_args,ospf_pid, ospf_ip, ospf_mask, ospf_area)) 
                thread_list.append(thread_item)
        for th in thread_list:
            th.start()   

    elif automations_list.get(automations_list.curselection()) == 'Add Firewall Rule':  
        device_to_enable = [device_list.get(sel_ip) for sel_ip in list(device_list.curselection())] 
        if len(device_to_enable) == 0:
            messagebox.showwarning('Alert', 'Select first the devices you want \n to enable Add a firewall rule')    
            automations_list.selection_clear(0, 'end')


        else:
            device_to_enable = [device_list.get(sel_ip) for sel_ip in list(device_list.curselection())]
            device_to_enable_ip = []

            for backup_dev in device_to_enable:
                device_to_enable_ip.append(backup_dev[1])
            dec_key = create_key()
            cipher = Fernet(dec_key)
            thread_list = []
            for dev_ip in device_to_enable_ip:
                with open('./Devices.csv', 'rt') as csv_f:
                    reader = csv.reader(csv_f, delimiter=',')
                    for row in reader:
                        if row[0] == dev_ip:
                            pwd_to_dec = row[5]
                            dev_type = row[2]
                acl_device_args = {'device_type': 'cisco_ios', 'ip': dev_ip, 'username': 'ihu', 'password': cipher.decrypt(pwd_to_dec.encode()).decode(), 'port': 22, 'verbose': True,'global_delay_factor': 2}            
                if (len(acl_nmb.get()) == 0 or len(source_ip.get()) == 0 or len(source_wildcard.get()) == 0 or len(destination_ip.get()) == 0 or len(destination_wildcard.get()) == 0 or acl_selected_type.get() == 'Select Action'):
                    messagebox.showwarning('Alert', 'All ACL parameters are necessary except protocol')
                else:
                    acl_number = acl_nmb.get()
                    acl_action = acl_selected_type.get()
                    acl_protocol = acl_selected_options.get()
                    acl_sourceip = source_ip.get()   
                    acl_sorce_wild = source_wildcard.get()
                    acl_destip = destination_ip.get()
                    acl_dest_wild = destination_wildcard.get()
                    thread_item = threading.Thread(target=acl_config,args=(acl_device_args, acl_number, acl_action, acl_protocol, acl_sourceip,acl_sorce_wild, acl_destip,acl_dest_wild,))
                    thread_list.append(thread_item)

            for th in thread_list:
                th.start()


# function to add devices to the Device.csv file

def add_device_to_file():
    if (len(new_device_ip_address.get()) == 0 or len(new_device_password.get()) == 0 or new_device_selected_type.get() == 'Select Device Type' or len(new_device_name.get()) == 0 or len(new_device_ssh_username.get()) == 0 or len(new_device_ssh_pass.get()) == 0):
        messagebox.showwarning('Alert', 'Device informations can not be left blank ')   
        print(len(new_device_ip_address.get()), len(new_device_password.get()), new_device_selected_type.get(),len(new_device_name.get()), len(new_device_ssh_username.get()), len(new_device_ssh_pass.get())) 

    else:
        if ip_entered(new_device_ip_address_entry.get()) == 0:
            pass
        else:
            pwd_window = Toplevel(root)
            master_password = StringVar()
            pwd_window.title('Encryption password')
            xpos = 10
            ypos = 600
            wgeo = '300x200+' + str(xpos) + '+' + str(ypos)
            pwd_window.geometry(wgeo)
            pwd_window.configure(background='white')
            pwd_window.resizable(False, False)
            pwd_window.grab_set()
            Label(pwd_window, text='Please enter Master Password',font='Arial 15 bold ', bg='white').pack(side=TOP)
            master_password_entry = Entry(pwd_window, textvariable=master_password, show="*",width=30, font='Helvetica11')
            master_password_entry.pack(side=TOP)
            master_password_entry.focus()
            pwd_ok_btn = Button(pwd_window, text=" OK ", width=15,height=1,font='Arial 15 bold', command=pwd_window.destroy)
            pwd_ok_btn.pack(side=BOTTOM, pady=15)
# messagebox.showwarning('Alert', 'Please check the weight!')
            pwd_window.attributes('-topmost', 1)
            root.wait_window(pwd_window)
            encryption_pwd = master_password.get()
            enc_key = get_key(encryption_pwd).decode()
            cipher = Fernet(enc_key)
            with open('./Devices.csv', 'a+', newline='') as write_obj:
                csv_writer = writer(write_obj)
                new_device_row = [new_device_ip_address.get(),cipher.encrypt(new_device_password.get().encode()).decode(),new_device_selected_type.get(),new_device_name.get(),new_device_ssh_username.get(),cipher.encrypt(new_device_ssh_pass.get().encode()).decode()]
                csv_writer.writerow(new_device_row)
                messagebox.showinfo('Success', 'Device successfully added!')


def clear_add_device():
    new_device_ip_address_entry.delete(0, 'end')
    new_device_password_entry.delete(0, 'end')
    new_device_name_entry.delete(0, 'end')
    new_device_ssh_username_entry.delete(0, 'end')
    new_device_ssh_pass_entry.delete(0, 'end')
    new_device_selected_type.set('Select Device Type')


def get_backup_options(selected_type):
    global manual_config_name
    if selected_type == 'Date_First':
        c_ip_date.set(0)
        c_manual.set(0)
        for child in manual_file_frame.winfo_children():
            child.pack_forget()
    elif selected_type == 'IP_First':
        c_date_ip.set(0)
        c_manual.set(0)
        for child in manual_file_frame.winfo_children():
            child.pack_forget()
    elif selected_type == 'Manual':
        c_date_ip.set(0)
        c_ip_date.set(0)
        filename_lbl.pack(side=LEFT)
        manual_file_frame.pack(side=TOP)
        dev_ip_lbl.pack(side=LEFT)
        manual_entry.pack(pady=5)
    elif selected_type == 'Recent':
        c_manual_ask.set(0)
    elif selected_type == 'Ask':
        c_last.set(0)




def getdevices(selected_type):
    device_list.delete(0, END)
    if selected_type == 'All':
        c_router.set(0)
        c_switch.set(0)
    elif selected_type == 'Router':
        c_all.set(0)
        c_switch.set(0)
    elif selected_type == 'Switch':
        c_all.set(0)
        c_router.set(0)

    
    if selected_type == 'All':
        with open('./Devices.csv', newline='') as f:
            reader = csv.reader(f)
            devices_to_list = [list(row) for row in reader]
            devices_to_list.pop(0)

        
        for device_to_add in devices_to_list:
            device_to_add.pop(5)
            device_to_add.pop(4)
            device_to_add.pop(1)
            device_to_add.insert(0, 'IP:')
            device_to_add.insert(2, '__Type:')
            device_to_add.insert(4, '__Hostname:')
            device_list.insert(0, device_to_add)

    elif selected_type == 'Router':     
        with open('./Devices.csv', newline='') as f:
            reader = csv.reader(f)
            devices_to_list = [list(row) for row in reader]
            devices_to_list.pop(0)  

        for device_to_add in devices_to_list:
            if device_to_add[2] == 'Router':
                device_to_add.pop(5)
                device_to_add.pop(4)
                device_to_add.pop(1)
                device_to_add.insert(0, 'IP:')
                device_to_add.insert(2, '__Type:')
                device_to_add.insert(4, '__Hostname:')
                device_list.insert(0, device_to_add)

    elif selected_type == 'Switch':
        with open('./Devices.csv', newline='') as f:
            reader = csv.reader(f)
            devices_to_list = [list(row) for row in reader]
            devices_to_list.pop(0)

        for device_to_add in devices_to_list:
            if device_to_add[2] == 'Switch':
                device_to_add.pop(5)
                device_to_add.pop(4)
                device_to_add.pop(1)
                device_to_add.insert(0, 'IP:')
                device_to_add.insert(2, '__Type:')
                device_to_add.insert(4, '__Hostname:')
                device_list.insert(0, device_to_add)





root = Tk()
root.title('IHU Network Automation Application ')
def_font = tkinter.font.nametofont("TkDefaultFont")
def_font.config(size=10, family='Verdana')
# root.iconbitmap('c:/Users/g.milios/PycharmProjects/QA Reports/im-ages/rtgr_logo_w_symbol.ico')
w, h = root.winfo_screenwidth(), root.winfo_screenheight()
root.state('iconic')
root.config(bg='#407294')




device_add_frame_lbl = Label(text="Add new device:", font='Helvetica 11', bg='#e6e6fa')
device_filter_frame_lbl = Label(text="Filters:", font='Helvetica 11', bg='#e6e6fa')
devices_frame_lbl = Label(text="Network Devices", font='Helvetica 11', bg='#407294')
automations_frame_lbl = Label(text="Automation Actions", font='Helvet-ica 11', bg='#407294')
automation_conf_frame_lbl = Label(text="Automation Action Configurations", font='Helvetica 25', bg='#407294')




info_frame = LabelFrame(root, padx=5, pady=5, bg='#407294')
left_sub_frame = Frame(root, padx=5, relief=FLAT, bg='#407294')
device_filter_frame = LabelFrame(left_sub_frame, labelwidget=device_filter_frame_lbl, padx=5, bg='#e6e6fa', relief=FLAT)
devices_frame = LabelFrame(left_sub_frame, labelwidget=devices_frame_lbl, padx=5, relief=FLAT, bg='#407294')
automations_frame = LabelFrame(left_sub_frame, labelwidget=automations_frame_lbl, padx=5, relief=FLAT, bg='#407294')
buttons_frame = Frame(info_frame, padx=5, relief=FLAT, bg='#407294')
output_frame = Frame(root, padx=5, bg='#407294', relief=SUNKEN)
device_add_frame = LabelFrame(info_frame, labelwidget=device_add_frame_lbl, padx=5, bg='#e6e6fa', relief=FLAT)
img_frame = Frame(root, padx=5, relief=FLAT, bg='#f0f0f0')
automation_conf_frame = LabelFrame(root, labelwidget=automation_conf_frame_lbl, padx=5, relief=SUNKEN, bg='#407294',
labelanchor='n')
manual_file_frame = Frame(automation_conf_frame, padx=5, pady=15, relief=FLAT, bg='#407294')


ospf_main_frm = Frame(automation_conf_frame, relief=FLAT,bg='#407294', pady=15)
ospf_device_frm = LabelFrame(ospf_main_frm, relief=SUNKEN,bg='#407294', pady=15)
ospf_process_id_frm = LabelFrame(ospf_main_frm, padx=2, relief=SUNKEN,bg='#407294', pady=15)
ospf_ip_frm = LabelFrame(ospf_main_frm, padx=5, relief=SUNKEN,bg='#407294', pady=15)
ospf_mask_frm = LabelFrame(ospf_main_frm, padx=5, relief=SUNKEN,bg='#407294', pady=15)

ospf_area_id_frm = LabelFrame(ospf_main_frm, padx=5, relief=SUNKEN,bg='#407294', pady=15)
ospf_device_lbl = Label(ospf_device_frm, text='Device IP\n--------------', font=('Aria', 15, 'bold'), fg='black',
anchor='w', bg='#407294')
ospf_process_id_lbl = Label(ospf_process_id_frm, text='process-id\n-----------', font=('Aria', 15, 'bold'),
fg='black', anchor='w', bg='#407294')
ospf_ip_lbl = Label(ospf_ip_frm, text='Network IP\n--------------',font=('Aria', 15, 'bold'), fg='black', anchor='w',bg='#407294')
ospf_mask_lbl = Label(ospf_mask_frm, text='Subnet mask\n------------',font=('Aria', 15, 'bold'), fg='black',anchor='w', bg='#407294')
ospf_area_id_lbl = Label(ospf_area_id_frm, text='Area-id\n--------',font=('Aria', 15, 'bold'), fg='black', anchor='w',bg='#407294')

automation_filter_frame_lbl = Label(text="Options: ", font='Helvetica 18 ',bg='white')
automation_filter_frame = LabelFrame(automation_conf_frame, labelwidget=automation_filter_frame_lbl,padx=5, relief=FLAT, bg='white',labelanchor='w')
backup_name_lbl = Label(automation_conf_frame, text="Filenames configuration ",font='Helvetica 25 bold', bg='#407294')
c_date_ip, c_ip_date, c_manual = IntVar(), IntVar(), IntVar()
cbtn_date_ip = Checkbutton(automation_filter_frame, text="Date First",variable=c_date_ip,onvalue=1, offvalue=0, state=NORMAL)
cbtn_ip_date = Checkbutton(automation_filter_frame, text="IP First",variable=c_ip_date,onvalue=1, offvalue=0, state=NORMAL)
cbtn_manual = Checkbutton(automation_filter_frame, text="Manual", variable=c_manual,onvalue=1, offvalue=0, state=NORMAL)
cbtn_date_ip.configure(command=partial(get_backup_options,'Date_First'), bg='white')
cbtn_ip_date.configure(command=partial(get_backup_options,'IP_First'), bg='white')
cbtn_manual.configure(command=partial(get_backup_options, 'Manual'),bg='white')


manual_config_name = StringVar()
manual_entry = Entry(manual_file_frame, textvariable=manual_config_name,width=30, font='Helvetica 11')
filename_lbl = Label(manual_file_frame, text="Filename: ",font='Helvetica 18 bold', bg='#407294')
dev_ip_lbl = Label(manual_file_frame, text="Device IP_ ",font='Helvetica 15', bg='#407294')

automation_restore_options_frame_lbl = Label(text="Options: ",font='Helvetica 18 bold',bg='white')
automation_restore_options_frame = LabelFrame(automation_conf_frame,
labelwidget=automation_restore_options_frame_lbl,padx=5, relief=FLAT,bg='white', labelanchor='w')
restore_name_lbl = Label(automation_conf_frame, text="Files to restore",font='Helvetica 25 bold', bg='#407294')

c_last, c_manual_ask = IntVar(), IntVar()
cbtn_last = Checkbutton(automation_restore_options_frame, text="Restore most recent backup", variable=c_last,onvalue=1, offvalue=0, state=NORMAL)
cbtn_manual_ask = Checkbutton(automation_restore_options_frame,
text="Manual restore", variable=c_manual_ask,
onvalue=1, offvalue=0, state=NORMAL)
cbtn_last.configure(command=partial(get_backup_options, 'Recent'),bg='white')
cbtn_manual_ask.configure(command=partial(get_backup_options, 'Ask'),bg='white')


acl_number_frm = Frame(automation_conf_frame, relief=FLAT,bg='#407294', pady=15)
acl_type_frm = Frame(automation_conf_frame, relief=FLAT, bg='#407294',pady=15)
acl_options_frm = Frame(automation_conf_frame, relief=FLAT,bg='#407294', pady=15)
acl_source_frm = Frame(automation_conf_frame, relief=FLAT,bg='#407294', pady=15)
acl_swildcard_frm = Frame(automation_conf_frame, relief=FLAT,bg='#407294', pady=15)
acl_des_frm = Frame(automation_conf_frame, relief=FLAT, bg='#407294',pady=15)
acl_dwildcard_frm = Frame(automation_conf_frame, relief=FLAT,bg='#407294', pady=15)

acl_number_lbl = Label(acl_number_frm, text='Aceess List number',font=('Aria', 15, 'bold'), fg='black',anchor='w', bg='#407294')
acl_type_lbl = Label(acl_type_frm, text='Type', font=('Aria', 15,'bold'), fg='black',anchor='w', bg='#407294')
acl_protocol_lbl = Label(acl_options_frm, text='Options',font=('Aria', 15, 'bold'), fg='black',anchor='w', bg='#407294')
acl_source_lbl = Label(acl_source_frm, text='Source', font=('Aria',15, 'bold'), fg='black',anchor='w', bg='#407294')
acl_swildcard_lbl = Label(acl_swildcard_frm, text='wildcard',font=('Aria', 15, 'bold'), fg='black',anchor='w', bg='#407294')
acl_des_lbl = Label(acl_des_frm, text='Destination', font=('Aria', 15,'bold'), fg='black',anchor='w', bg='#407294')
acl_dwildcard_lbl = Label(acl_dwildcard_frm, text='wildcard',font=('Aria', 15, 'bold'), fg='black',anchor='w', bg='#407294')


acl_selected_type = StringVar()
acl_selected_type.set('Select Action')
acl_selected_type_options = ['permit', 'deny']
acl_types = OptionMenu(acl_type_frm, acl_selected_type, *acl_selected_type_options)
acl_types.config(width=15, bg='dark grey')
acl_types["highlightthickness"] = 1


acl_selected_options = StringVar()
acl_selected_options.set('Select Protocol')
acl_selected_options_options = ['ICMP', 'TCP', 'UDP']
acl_options = OptionMenu(acl_options_frm, acl_selected_options,*acl_selected_options_options)
acl_options.config(width=15, bg='dark grey')
acl_options["highlightthickness"] = 1

acl_nmb, source_ip, source_wildcard, destination_ip, destination_wildcard = StringVar(), StringVar(), StringVar(),StringVar(), StringVar()
acl_nmb_entry = Entry(acl_number_frm, textvariable=acl_nmb, width=15, font='Helvetica 11')
source_ip_entry = Entry(acl_source_frm, textvariable=source_ip, width=15, font='Helvetica 11')
source_wildcard_entry = Entry(acl_swildcard_frm, textvariable=source_wildcard,width=15, font='Helvetica 11')
destination_ip_entry = Entry(acl_des_frm, textvariable=destination_ip,width=15, font='Helvetica 11')
destination_wildcard_entry = Entry(acl_dwildcard_frm, textvariable=destination_wildcard,width=15, font='Helvetica 11')


bgimg = ImageTk.PhotoImage(Image.open('./Joseph_Seed.png').resize((300, 93)), Image.ANTIALIAS)
bg_lbl = Label(img_frame, image=bgimg)

output_description = Text(output_frame)
output_description.insert('1.0', 'output of the commands will be shown here')
v_device_list = Scrollbar(devices_frame, orient=VERTICAL,bg='#ffffff')
v_output = Scrollbar(output_frame, orient=VERTICAL, bg='#ffffff')
v_automation_actions = Scrollbar(automations_frame, orient=VERTICAL,bg='#ffffff')

device_list = Listbox(devices_frame, selectmode="multiple", exportselection=False, yscrollcommand=v_device_list.set)
device_list.config(width=45, height=14, font='Arial 11', activestyle='none')
automations_list = Listbox(automations_frame, selectmode="single", exportselection=False,yscrollcommand=v_automation_actions.set)

automations_list.config(width=45, height=8, font='Arial 11', activestyle='none')
automations_list.bind("<<ListboxSelect>>", get_config_name)
# configure scrollbars
v_device_list.config(command=device_list.yview)
v_output.config(command=output_description.yview)
v_automation_actions.config(command=automations_list.yview)


action_options = ['Enable OSPF', 'Add Firewall Rule', 'Restore Configuration', 'Backup Configuration']
for action_to_add in action_options:
    automations_list.insert(0, action_to_add)

c_all, c_router, c_switch = IntVar(), IntVar(), IntVar()
cbtn_all = Checkbutton(device_filter_frame, text="all", variable=c_all, onvalue=1, offvalue=0, state=NORMAL)
cbtn_router = Checkbutton(device_filter_frame, text="Router", variable=c_router, onvalue=1, offvalue=0, state=NORMAL)
cbtn_switch = Checkbutton(device_filter_frame, text="Switch", variable=c_switch, onvalue=1, offvalue=0, state=NORMAL)

cbtn_all.configure(command=partial(getdevices, 'All'))
cbtn_router.configure(command=partial(getdevices, 'Router'))
cbtn_switch.configure(command=partial(getdevices, 'Switch'))

exit_btn = Button(buttons_frame, text="Exit", width=32, height=2,command=root.destroy, bg='#bada55')
change_pass_btn = Button(buttons_frame, text="Change Password",width=32, height=2,command=password_change, bg='#bada55')
execute_btn = Button(automation_conf_frame, text="Execute", width=147,height=2,bg='#bada55', command=execute_automations,state='normal')
add_device_ok_btn = Button(device_add_frame, text="Add Device",width=16, height=2, command=add_device_to_file,bg='#bada55', state='normal')
add_device_clear_btn = Button(device_add_frame, text="Clear",width=16, height=2,command=clear_add_device, bg='#bada55')


new_device_ip_address, new_device_password, new_device_name, new_device_ssh_username, new_device_ssh_pass = StringVar(), StringVar(), StringVar(), StringVar(), StringVar()
new_device_ip_address_lbl = Label(device_add_frame, text="IP Address:", font='Helvetica 11 bold', bg='#e6e6fa')
new_device_password_lbl = Label(device_add_frame, text="Password:",font='Helvetica 11 bold', bg='#e6e6fa')
new_device_name_lbl = Label(device_add_frame, text="Description:",font='Helvetica 11 bold', bg='#e6e6fa')
new_device_ssh_username_lbl = Label(device_add_frame, text="SSH Login Username:",font='Helvetica 11 bold',bg='#e6e6fa')

new_device_ssh_pass_lbl = Label(device_add_frame, text="SSH Login Password:",font='Helvetica 11 bold',bg='#e6e6fa')

new_device_ip_address_entry = Entry(device_add_frame, textvariable=new_device_ip_address,width=30, font='Helvetica 11')
new_device_password_entry = Entry(device_add_frame, textvariable=new_device_password, show="*",width=30, font='Helvetica 11')
new_device_name_entry = Entry(device_add_frame, textvariable=new_device_name, width=30, font='Helvetica 11')
new_device_ssh_username_entry = Entry(device_add_frame, textvariable=new_device_ssh_username,width=30, font='Helvetica 11')
new_device_ssh_pass_entry = Entry(device_add_frame, textvariable=new_device_ssh_pass, show="*",width=30, font='Helvetica 11')

new_device_selected_type = StringVar(device_add_frame)
new_device_selected_type.set('Select Device Type')
new_device_type_options = ['Router', 'Switch']
new_device_types = OptionMenu(device_add_frame, new_device_selected_type, *new_device_type_options)
new_device_types.config(width=30, bg='dark grey')

new_device_ip_address_lbl.pack(pady=5)
new_device_ip_address_entry.pack(pady=5)
new_device_password_lbl.pack(pady=5)
new_device_password_entry.pack(pady=5)
new_device_name_lbl.pack(pady=5)
new_device_name_entry.pack(pady=5)
new_device_ssh_username_lbl.pack(pady=5)
new_device_ssh_username_entry.pack(pady=5)
new_device_ssh_pass_lbl.pack(pady=5)
new_device_ssh_pass_entry.pack(pady=5)
new_device_types.pack(pady=10)
add_device_ok_btn.pack(side=LEFT, padx=5, pady=5)
add_device_clear_btn.pack(side=LEFT, pady=5)

info_frame.pack(side=LEFT, fill=BOTH, padx=10, pady=10)
buttons_frame.pack(side=BOTTOM, anchor="n", padx=10, pady=10)
output_frame.pack(fill=BOTH, side=BOTTOM, pady=10)
img_frame.pack(fill=BOTH, side=TOP, pady=10)
left_sub_frame.pack(side=LEFT, fill=BOTH, pady=10)
bg_lbl.pack()
devices_frame.pack(anchor="nw")
device_filter_frame.pack(anchor="nw", padx=10, pady=5)
automations_frame.pack(anchor="nw")
device_add_frame.pack(anchor="nw", padx=10, pady=5)
automation_conf_frame.pack(side=LEFT, fill=BOTH)
v_device_list.pack(side=RIGHT, fill=Y)
device_list.pack(side=LEFT, anchor="n")

cbtn_all.pack(side=LEFT, anchor="n", padx=29, pady=5)
cbtn_router.pack(side=LEFT, anchor="n", padx=29, pady=5)
cbtn_switch.pack(side=LEFT, anchor="n", padx=29, pady=5)
v_automation_actions.pack(side=RIGHT, fill=Y)
automations_list.pack(side=LEFT, anchor="n")
exit_btn.pack(anchor="s", side=BOTTOM, pady=5)
change_pass_btn.pack(anchor="s", side=BOTTOM, pady=5)
execute_btn.pack(side=BOTTOM, pady=5)
v_output.pack(side=RIGHT, fill=Y)
output_description.pack(fill=BOTH, side=BOTTOM)
root.mainloop()