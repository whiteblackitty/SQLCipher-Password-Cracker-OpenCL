#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import pyopencl as cl
import numpy as np

class opencl_information: # opencl information class by B. Kerler

    def __init__(self):
        pass
    
    def printplatforms(self):
        platformNum=0
        for platform in cl.get_platforms():
            print('Platform %d - Name %s, Vendor %s' %(platformNum, platform.name, platform.vendor))
            platformNum+=1

    def printfullinfo(self):
        print('\n' + '=' * 60 + '\nOpenCL Platforms and Devices')
        platformNum=0
        for platform in cl.get_platforms():
            print('=' * 60)
            print('Platform %d - Name: ' %platformNum + platform.name)
            print('Platform %d - Vendor: ' %platformNum + platform.vendor)
            print('Platform %d - Version: ' %platformNum + platform.version)
            print('Platform %d - Profile: ' %platformNum + platform.profile)

            for device in platform.get_devices():
                print(' ' + '-' * 56)
                print(' Device - Name: ' \
                      + device.name)
                print(' Device - Type: ' \
                      + cl.device_type.to_string(device.type))
                print(' Device - Max Clock Speed: {0} Mhz' \
                      .format(device.max_clock_frequency))
                print(' Device - Compute Units: {0}' \
                      .format(device.max_compute_units))
                print(' Device - Local Memory: {0:.0f} KB' \
                      .format(device.local_mem_size / 1024.0))
                print(' Device - Constant Memory: {0:.0f} KB' \
                      .format(device.max_constant_buffer_size / 1024.0))
                print(' Device - Global Memory: {0:.0f} GB' \
                      .format(device.global_mem_size / 1073741824.0))
                print(' Device - Max Buffer/Image Size: {0:.0f} MB' \
                      .format(device.max_mem_alloc_size / 1048576.0))
                print(' Device - Max Work Group Size: {0:.0f}' \
                      .format(device.max_work_group_size))
                print('\n')
            platformNum+=1


class pbkdf2_aes_opencl:

    OPENCL_CODE_PATH=os.path.join(os.path.dirname(__file__),"pbkdf2-sha1_aes-256-cbc.cl")

    def __init__(self,platform,pbkdf_salt,aes_iv,encrypted_data):
        
        platforms = cl.get_platforms()
        if (platform > len(platforms)):
            assert("Selected platform %d doesn't exist" % platform)

        saltlen = int(len(pbkdf_salt))
        if (saltlen>int(64)):
            print('Salt longer than 64 chars is not supported!')
            exit(0)

        self.pbkdf_salt=np.fromstring(pbkdf_salt, dtype=np.uint32)
        self.aes_iv=np.fromstring(aes_iv,dtype=np.uint8)
        self.encrypted_data=np.fromstring(encrypted_data,dtype=np.uint8)

        # Get platforms
        devices = platforms[platform].get_devices()
        # Create context for GPU/CPU
        print("Using Platform %d:" % platform)
        self.ctx = cl.Context(devices)
        
        for device in devices:
            print('--------------------------------------------------------------------------')
            print(' Device - Name: '+ device.name)
            print(' Device - Type: '+ cl.device_type.to_string(device.type))
            print(' Device - Compute Units: {0}'.format(device.max_compute_units))
            print(' Device - Max Work Group Size: {0:.0f}'.format(device.max_work_group_size))

        # Create queue for each kernel execution, here we only use 1 device
        self.queue = cl.CommandQueue(self.ctx,devices[0],cl.command_queue_properties.PROFILING_ENABLE)
    

    def compile(self,marcos=dict,writeProcessedOpenCLCode=False):
        ori_src =""
        with open(self.OPENCL_CODE_PATH, "r") as rf:
            ori_src += rf.read()

        proc_src=""
        for line in ori_src.splitlines():
            if marcos:# processed all the needed marcos
                for k,v in marcos.items():
                    if line.startswith("#define "+k+" "):
                        line="#define "+k+" "+v# re-define marcos
                        del(marcos[k])
                        break
            proc_src += line+"\n"
        if marcos:
            print("Error! No matched marcos in "+self.OPENCL_CODE_PATH+" :")
            for k,v in marcos.iteritems():
                print(k)
        if writeProcessedOpenCLCode:
            with open(os.path.join(os.path.dirname(self.OPENCL_CODE_PATH),"processed.cl"), "w", encoding='utf-8') as f:
                f.write(proc_src)

        # Kernel function instantiation
        self.prg = cl.Program(self.ctx, proc_src).build()


    def run(self,password_start,password_step,printspeed=True):

        pwdim = (password_step,)# set a 1-dimension tuple to tell the runtime to generate a totalpws of kernel execution
        
        mf = cl.mem_flags# opencl memflag enum
        
        pass_g =  cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=np.array(password_start,dtype=np.uint64))
        salt_g = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=self.pbkdf_salt)
        iv_g = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=self.aes_iv)
        data_g = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=self.encrypted_data)

        result = np.zeros(password_step, dtype=np.bool)# np.zeros(numberOftheElement,elementType) name should be sync with the "result variable" in OpenCL code
        result_g = cl.Buffer(self.ctx, mf.WRITE_ONLY, result.nbytes)# size should be in byte, 1byte=8bit; notice that in python, bool=8bit=1byte

        # The total time GPU used can be indicated by measuring the finish_event-start_event
        #******************Call Kernel******************
        start_event=cl.enqueue_marker(self.queue)
        finish_event=self.prg.func_pbkdf2(self.queue, pwdim,(512,), pass_g, salt_g, iv_g, data_g, result_g)
        finish_event.wait()
        #******************Call Kernel****************** ,if set localsize (512,) to None,the runtime will automatically takes care of block/grid distribution

        if(printspeed):
            print("OpenCL Speed: "+str(password_step/1e-9/(finish_event.profile.END-start_event.profile.START)/1000)+" K passphrase/s")

        cl.enqueue_copy(self.queue, result, result_g)# copy the result from device to host,type of "result" is a list of unsigned integer(32bit,4byte)

        return np.transpose(np.nonzero(result))+password_start# the array number of nonzero value is written to a list added by password_start value


    
