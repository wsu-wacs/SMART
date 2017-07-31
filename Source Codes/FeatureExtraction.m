%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.


%sessions and their features

%% Load data
clc
clear
close all
pause(2)

[filename, pathname]=uigetfile({'*.*'},'Log file selector');
Path=[pathname filename];
load(Path)
Name=filename(1:length(filename)-4);
Name=[Name 'Sessions.mat'];
Name=[pathname '\' Name];
%% Session definition
[SessionNumber,SessionIndex]=SessionIdentifier(IP,UserAgent,DateTime);

%% Creation of Feature-seastion matrix
FeatureNumber=31;
Feature=zeros(SessionNumber,FeatureNumber);

%% Feature 1: Trap File request -> 1:call robots.txt
Temp=~cellfun(@isempty,strfind(File, 'robots.txt'));
for i=1:SessionNumber
    Feature(i,1)=sum(Temp(find(SessionIndex==i)))>0;
end

%% Feature 2: Session time -> Last request - First request *Sec
for i=1:SessionNumber
    Temp=find(SessionIndex==i);
    Feature(i,2)=etime(datevec(DateTime(Temp(end))),datevec(DateTime(Temp(1))));
end

%% Feature 3: Night -> Percentage of 00 up to 07AM requests [00,07)
for i=1:SessionNumber
    Temp=datevec(DateTime(find(SessionIndex==i)));
    Feature(i,3)=((sum(Temp(:,4)<7))/numel(Temp(:,4)))*100;
end

%% Feature 4: %Referrer -> Empty Referrer field= '' or '/' or '-'
Temp=strcmp(Referrer, '')+strcmp(Referrer, '/')+strcmp(Referrer, '-');
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,4)=(sum(Temp(RequestNumbers))/numel(RequestNumbers))*100;
end

%% Feature 5: SD-RPD -> standard devation of pages' depth
Temp=strfind(File,'/');
NumberRequest=size(Temp,1);
FileNumber=zeros(NumberRequest,1);
for i=1:NumberRequest
    Slashes=Temp{i,1};
    % Omiting root path "/" and just folders "/.../.../" to concider just
    % pages , also there is no pages when root is not observed
    if(numel(Slashes)==0 || Slashes(end)==length(str2mat(File(i)))),continue,end
    FileNumber(i)=numel(Slashes); % "-" or "" is not considered because do not contain any page
end

for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,5)=std(FileNumber(RequestNumbers));
end

%% Feature 6: %CST -> Percentage of consequative requests from similar directory
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    if(numel(RequestNumbers)==1),continue,end % a session with one request -> %CST=0%
    Temp=strfind(File(RequestNumbers),'/');
    % Directory: "/.../.../"-> up to latest Slash and do not consider the file
    Temp2=Temp{1,1};% Places of Slashes of File field of this request
    FirstDirectory=str2mat(File(RequestNumbers(1)));
    if(numel(Temp2)>0)
        FirstDirectory=FirstDirectory(1:Temp2(end));% Just directory
    end
    
    for j=2:numel(RequestNumbers)
        Temp3=Temp{j,1};
        SecondDirectory=str2mat(File(RequestNumbers(j)));
        if(numel(Temp3)>0)
            SecondDirectory=SecondDirectory(1:Temp3(end));
        end
        if(numel(Temp3)~=0 && numel(Temp2)~=0)% whiout root shows there is no directory to change
            Feature(i,6)=Feature(i,6)+strcmp(FirstDirectory,SecondDirectory);
        end
        Temp2=Temp3;
        FirstDirectory=SecondDirectory;
    end
    Feature(i,6)=(Feature(i,6)/(numel(RequestNumbers)-1))*100;
end

%% Feature 7: %CSB -> the transformed volume

for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,7)=sum(DataVolume(RequestNumbers));
end

%% Feature 8: AvgTime -> average interval time between two consequative sessions**
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    IntervalNumber=numel(RequestNumbers)-1;
    if(IntervalNumber==0),continue,end
    Temp=etime(datevec(DateTime(RequestNumbers(2:end))),datevec(DateTime(RequestNumbers(1:end-1))));
    Feature(i,8)=sum(Temp)/IntervalNumber;
end

%% Feature 9: %Head**
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,9)=(sum(strcmp(HttpMethod(RequestNumbers),'head'))/numel(RequestNumbers))*100;
end

%% Feature 10: %4xx
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,10)=(sum(floor(str2double(ErrorCode(RequestNumbers))/100)==4)/numel(RequestNumbers))*100;
end

%% Feature 11: Penalty -> counter of new changes in Referrer field that have been seen previously
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    if(numel(RequestNumbers)==1),continue,end % a session with one request -> Penalty=0
    Temp=Referrer(find(~strcmp(Referrer(RequestNumbers(1:end-1)),Referrer(RequestNumbers(2:end)))));
    if(numel(Temp)==0),continue,end% There is no any change
    if(~strcmp(Temp(end),Referrer(RequestNumbers(end)))),Temp=[Temp; Referrer(RequestNumbers(end))];end
    Feature(i,11)=numel(Temp)-numel(unique(Temp));
end

%% Feature 12: Max Barrage -> the number of browser files
BrowserType={'php';'ajax';'json';'tpl';'html';'htm';'jsp';'net';'mhtml';'mht';'asp';'aspx';'css';'js';'woff';'ttf';'eot';'xml'};
BrowserType=lower(BrowserType);
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    Temp=strfind(File(RequestNumbers),'/');
    % File Place: '/.../.../'+FileName . Filetyp
    for j=1:numel(RequestNumbers)
        Temp2=Temp{j,1};
        Directory=str2mat(File(RequestNumbers(j)));
        %Do not have file: Do not contain root and be just dirctory '/.../'
        if(numel(Temp2)==0 || length(Directory)<=Temp2(end)),continue,end
        FileType=Directory(Temp2(end)+1:end);
        Temp2=find(FileType=='.',1,'last');
        FileType=FileType(Temp2+1:end);
        if(sum(strcmp(FileType,BrowserType)))
            Feature(i,12)=Feature(i,12)+1;
        end
    end
end

%% Feature 13: SD-FileType -> Switch Factor File Type
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    if(numel(RequestNumbers)==1),continue,end % a session with one request -> SF-FileType=0%
    Temp=strfind(File(RequestNumbers),'/');
    % File Place: '/.../.../'+FileName . Filetyp
    Temp2=Temp{1,1};% Places of Slashes of File field of this request
    FirstDirectory=str2mat(File(RequestNumbers(1)));
    %Do not have file: Do not contain root and be just dirctory '/.../'
    if(numel(Temp2)>0 && length(FirstDirectory)>Temp2(end))
        FirstType=FirstDirectory(Temp2(end)+1:end);% Just File
        Temp2=find(FirstType=='.',1,'last');
        if(numel(Temp2)>0)
            FirstType=FirstType(Temp2+1:end);
        else
            FirstType='File';%A file without certain clear type
        end
    else
        FirstType=[];
    end
    
    for j=2:numel(RequestNumbers)
        Temp3=Temp{j,1};
        SecondDirectory=str2mat(File(RequestNumbers(j)));
        if(numel(Temp3)>0 && length(SecondDirectory)>Temp3(end))
            SecondType=SecondDirectory(Temp3(end)+1:end);% Just File
            Temp3=find(SecondType=='.',1,'last');
            if(numel(Temp3)>0)
                SecondType=SecondType(Temp3+1:end);
            else
                SecondType='File';
            end
        else
            SecondType=[];
        end
        % whiout root or just directory without file shows there is no File to change
        if(~isempty(FirstType) && ~isempty(SecondType))
            Feature(i,13)=Feature(i,13)+~strcmp(FirstType,SecondType);
        end
        FirstType=SecondType;
    end
end

%% Feature 14: SF-csbyte -> counting changes in data volume
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    if(numel(RequestNumbers)==1),continue,end % a session with one request -> SF-csbyte=0
    Feature(i,14)=numel(find(DataVolume(RequestNumbers(1:end-1))-DataVolume(RequestNumbers(2:end))~=0));
end

%% Feature 15: SF-referre
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    if(numel(RequestNumbers)==1),continue,end % a session with one request -> SF-referre=0
    Feature(i,15)=numel(find(~strcmp(Referrer(RequestNumbers(1:end-1)),Referrer(RequestNumbers(2:end)))));
end

%% Feature 16: Click number -> Number of requests in a session
for i=1:SessionNumber
    Feature(i,16)=numel(find(SessionIndex==i));
end

%% Feature 17: depth**
Temp=strfind(File,'/');
NumberRequest=size(Temp,1);
FileNumber=zeros(NumberRequest,1);
for i=1:NumberRequest
    Slashes=Temp{i,1};
    % Omiting root path "/" and just folders "/.../.../" to concider just
    % pages , also there is no pages when root is not observed
    if(numel(Slashes)==0 || Slashes(end)==length(str2mat(File(i)))),continue,end
    FileNumber(i)=numel(Slashes); % "-" or "" is not considered because do not contain any page
end

for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,17)=max(FileNumber(RequestNumbers));
end

%% Feature 18: total Html pages**
BrowserType={'html';'htm'};% BrowserType just to consider html pages
BrowserType=lower(BrowserType);
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    Temp=strfind(File(RequestNumbers),'/');
    % File Place: '/.../.../'+FileName . Filetyp
    for j=1:numel(RequestNumbers)
        Temp2=Temp{j,1};
        Directory=str2mat(File(RequestNumbers(j)));
        %Do not have file: Do not contain root and be just dirctory '/.../'
        if(numel(Temp2)==0 || length(Directory)<=Temp2(end)),continue,end
        FileType=Directory(Temp2(end)+1:end);
        Temp2=find(FileType=='.',1,'last');
        FileType=FileType(Temp2+1:end);
        if(sum(strcmp(FileType,BrowserType)))
            Feature(i,18)=Feature(i,18)+1;
        end
    end
end

%% Feature 19: PPI -> Page Popularity Index
BrowserType={'php';'ajax';'json';'tpl';'html';'htm';'jsp';'net';'mhtml';'mht';'asp';'aspx';'css';'js';'woff';'ttf';'eot';'xml'};
BrowserType=lower(BrowserType);
%>>>> PPI(i)=-log(Frequency of page(i)/Total number of requests in log file)
FileList=unique(File);% creation of a list of file which are unsimilar
Frequency=zeros(numel(FileList),1);
Temp=strfind(FileList,'/');
for i=1:numel(FileList)
    Temp2=Temp{i,1};
    % File Place: '/.../.../'+FileName . Filetyp
    Directory=str2mat(FileList(i));
    %Do not have file: Do not contain root and be just dirctory '/.../'
    if(numel(Temp2)==0 || length(Directory)<=Temp2(end)),continue,end
    FileType=Directory(Temp2(end)+1:end);
    Temp2=find(FileType=='.',1,'last');
    FileType=FileType(Temp2+1:end);
    if(sum(strcmp(FileType,BrowserType)))% It shows it is a file not just directory or -
      Frequency(i)=sum(strcmp(File,Directory));
    end
end
PPIFileList=-log(Frequency/numel(File));
PPIFileList(PPIFileList==Inf)=0;

%>>>>>> PPI_session(j)=sum[(max(PPI)-PPI(i))*number of request for page(i)
%in session (j)]/number of requests in session(j)
Maximum=max(PPIFileList);
PPIFileList=Maximum-PPIFileList;
PPIFileList(Frequency==0)=0;%No pages file should not consider
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    Number=[];
    for j=1:numel(RequestNumbers)
        Number=[Number find(strcmp(FileList,File(RequestNumbers(j))))];
    end
    Feature(i,19)=sum(PPIFileList(Number))/numel(RequestNumbers);
end

%% Feature 20: HTML/Image***
HTML={'html';'htm'};
Image={'gif'; 'jpeg'; 'jpg'; 'png'; 'ico'};
HTML=lower(HTML);
Image=lower(Image);
for i=1:SessionNumber
    HTMLType=0;
    ImageType=0;
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    Temp=strfind(File(RequestNumbers),'/');
    % File Place: '/.../.../'+FileName . Filetyp
    for j=1:numel(RequestNumbers)
        Temp2=Temp{j,1};
        Directory=str2mat(File(RequestNumbers(j)));
        %Do not have file: Do not contain root and be just dirctory '/.../'
        if(numel(Temp2)==0 || length(Directory)<=Temp2(end)),continue,end
        FileType=Directory(Temp2(end)+1:end);
        Temp2=find(FileType=='.',1,'last');
        FileType=FileType(Temp2+1:end);
        if(sum(strcmp(FileType,HTML)))
            HTMLType=HTMLType+1;
        elseif(sum(strcmp(FileType,Image)))
            ImageType=ImageType+1;
        end
    end
    
    if(HTMLType+ImageType==1 || HTMLType+ImageType==0)
        Feature(i,20)=1;
    elseif(ImageType==0 && HTMLType>1)
        Feature(i,20)=-1;
    else
        Feature(i,20)=HTMLType/ImageType;
    end
end
Feature((find(Feature(:,20)==-1)),20)=max(Feature(:,20));

%% Feature 21: %Zip
ZipType={'zip';'gz'};
ZipType=lower(ZipType);
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    Temp=strfind(File(RequestNumbers),'/');
    % File Place: '/.../.../'+FileName . Filetyp
    for j=1:numel(RequestNumbers)
        Temp2=Temp{j,1};
        Directory=str2mat(File(RequestNumbers(j)));
        %Do not have file: Do not contain root and be just dirctory '/.../'
        if(numel(Temp2)==0 || length(Directory)<=Temp2(end)),continue,end
        FileType=Directory(Temp2(end)+1:end);
        Temp2=find(FileType=='.',1,'last');
        FileType=FileType(Temp2+1:end);
        if(sum(strcmp(FileType,ZipType)))
            Feature(i,21)=Feature(i,21)+1;
        end
    end
    Feature(i,21)=(Feature(i,21)/numel(RequestNumbers))*100;
end

%% Feature 22: Binary Doc
SelectedType={'ps';'pdf';'doc';'docx'};
SelectedType=lower(SelectedType);
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    Temp=strfind(File(RequestNumbers),'/');
    % File Place: '/.../.../'+FileName . Filetyp
    for j=1:numel(RequestNumbers)
        Temp2=Temp{j,1};
        Directory=str2mat(File(RequestNumbers(j)));
        %Do not have file: Do not contain root and be just dirctory '/.../'
        if(numel(Temp2)==0 || length(Directory)<=Temp2(end)),continue,end
        FileType=Directory(Temp2(end)+1:end);
        Temp2=find(FileType=='.',1,'last');
        FileType=FileType(Temp2+1:end);
        if(sum(strcmp(FileType,SelectedType)))
            Feature(i,22)=Feature(i,22)+1;
        end
    end
    Feature(i,22)=(Feature(i,22)/numel(RequestNumbers))*100;
end

%% Feature 23: Binary Exec
SelectedType={'cgi';'exe'};
SelectedType=lower(SelectedType);
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    Temp=strfind(File(RequestNumbers),'/');
    % File Place: '/.../.../'+FileName . Filetyp
    for j=1:numel(RequestNumbers)
        Temp2=Temp{j,1};
        Directory=str2mat(File(RequestNumbers(j)));
        %Do not have file: Do not contain root and be just dirctory '/.../'
        if(numel(Temp2)==0 || length(Directory)<=Temp2(end)),continue,end
        FileType=Directory(Temp2(end)+1:end);
        Temp2=find(FileType=='.',1,'last');
        FileType=FileType(Temp2+1:end);
        if(sum(strcmp(FileType,SelectedType)))
            Feature(i,23)=Feature(i,23)+1;
        end
    end
    Feature(i,23)=(Feature(i,23)/numel(RequestNumbers))*100;
end

%% Feature 24: MultiIP -> Multple IP:1 / Unique IP:0
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,24)=((sum(strcmp(IP(RequestNumbers),IP(RequestNumbers(1)))))~=numel(RequestNumbers));
end

%% Feature 25: MultiAgent -> Multple UserAgent:1 / Unique UserAgent:0
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,25)=((sum(strcmp(UserAgent(RequestNumbers),UserAgent(RequestNumbers(1)))))~=numel(RequestNumbers));
end

%% Feature 26: %304
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,26)=(sum(strcmp(ErrorCode(RequestNumbers),'304'))/numel(RequestNumbers))*100;
end

%% Feature 27: MultiMedia
SelectedType={
            %%audioFiles
            '2sf';'2sflib';'3ga';'4mp';'5xb';'5xe';'5xs';'669';'6cm';'8cm';'8med';'8svx';'a2b';'a2i';'a2m';'a2p';'a2t';'a2w';'a52';'aa';'aa3';
            'aac';'aax';'ab';'abc';'abm';'ac3';'acd';'acd-bak';'acd-zip';'acm';'acp';'act';'adg';'adt';'adts';'adv';'afc';'agm';'agr';'ahx';'aif';'aifc';
            'aiff';'aimppl';'ais';'akp';'al';'alac';'alaw';'alc';'all';'als';'amf';'amr';'ams';'amxd';'amz';'aob';'ape';'apf';'apl';'aria';'ariax';'asd';
            'ase';'at3';'atrac';'au';'aud';'aup';'avastsounds';'avr';'awb';'ay';'b4s';'band';'bap';'bcs';'bdd';'bidule';'bnk';'bonk';'box';'brstm';'bun';'bwf';
            'bwg';'bww';'c01';'caf';'caff';'cda';'cdda';'cdlx';'cdo';'cdr';'cel';'cfa';'cfxr';'cgrp';'cidb';'ckb';'ckf';'cmf';'conform';'copy';'cpr';
            'cpt';'csh';'cts';'cwb';'cwp';'cwt';'d00';'d01';'dcf';'dcm';'dct';'ddt';'dewf';'df2';'dfc';'dff';'dig';'djr';'dls';'dm';'dmc';'dmf';'dmsa';
            'dmse';'dra';'drg';'ds';'ds2';'dsf';'dsm';'dsp';'dss';'dtm';'dts';'dtshd';'dvf';'dw';'dwa';'dwd';'ear';'efa';'efe';'efk';'efq';'efs';'efv';
            'emd';'emp';'emx';'emy';'eop';'esps';'evr';'expressionmap';'f2r';'f32';'f3r';'f4a';'f64';'far';'fda';'fdp';'fev';'fff';'flac';'flp';'fls';
            'fpa';'frg';'fsb';'fsm';'ftm';'ftmx';'fzb';'fzf';'fzv';'g721';'';'g726';'gbproj';'gbs';
            'gig';'gio';'gm';'gp5';'gpbank';'gpk';'gpx';'gro';'groove';'gsm';'h0';'h3b';'h3e';'';'h4e';'h5b';'';'h5s';'';'hbe';'';'hdp';'hma';'';'hsb';'';'ics';'iff';'';'igr';'';'imp';'';'isma';'it';'';'itls';'its';'jam';'jo';'jo-7z';'k25';'k26';'kar';'kfn';'kin';'kit';'kmp';'koz';'kpl';'krz';'ksc';'ksd';'ksf';'ksm';'kt2';'kt3';'ktp';'l';'la';'lof';
            'logic';'lqt';'lso';'lvp';'lwv';
            'm1a';'m3u';'m3u8';'m4a';'m4b';'m4p';'m4r';'ma1';'mbr';'mdc';'mdl';'med';'mgv';'mid';'midi';'mini2sf';'minincsf';'minipsf';'minipsf2';'miniusf';'mka';
            'mlp';'mmf';'mmm';'mmp';'mmpz';'mo3';'mod';'mogg';'mp1';'mp2';'mp3';'mpa';'mpc';'mpdp';'mpga';'mpu';'mp_';'mscx';'mscz';'msv';'mt2';'mt9';
            'mte';'mtf';'mti';'mtm';'mtp';'mts';'mu3';'mui';'mus';'musa';'musx';'mux';'muz';'mwand';'mws';'mx3';'mx4';'mx5';'mx5template';'mxl';'mxmf';'myr';'mzp';'nap';'narrative';'nbs';'ncw';
            'nkb';'nkc';'nki';'nkm';'nks';'nkx';'nml';'nmsv';'note';'npl';'nra';'nrt';'nsa';'nsf';'nst';'ntn';'nvf';'nwc';'obw';'odm';'ofr';'oga';'ogg';'okt';'oma';'omf';'omg';'omx';'opus';'orc';'ots';'ove';'ovw';'pac';'pandora';'pat';'pbf';'pca';'pcast';'pcg';'pcm';'pd';'peak';'pek';'pho';'phy';'pjunoxl';'pk';'pkf';'pla';'pls';'plst';'ply';'pna';'pno';'ppc';'ppcx';'prg';'psf';'psf1';'psf2';'psm';'psy';'ptcop';'ptf';'ptm';'pts';
            'ptx';'pvc';'q1';'q2';'qcp';'r';'r1m';'ra';'rad';'ram';'raw';'rax';'rbs';'rcy';'record';'rex';'rfl';'rgrp';'rip';'rmf';'rmi';'rmj';
            'rmm';'rsf';'rsn';'rso';'rta';'rti';'rtm';'rts';'rvx';'rx2';'s3i';'s3m';'s3z';'saf';'sam';'sap';'sb';'sbg';'sbi';'sbk';'sc2';'scs11';'sd';'sd2';'sd2f';'sdat';'sdii';'sds';'sdt';'sdx';'seg';'seq';'ses';'sesx';'sf';'sf2';'sfap0';'sfk';'sfl';'sfpack';'sfs';'sgp';'shn';'sib';'sid';'slp';'slx';'sma';
            'smf';'smp';'smpx';'snd';'sng';'sns';'snsf';'sou';'sph';'sppack';'sprg';'spx';'sseq';'ssnd';
            'stap';'sth';'sti';'stm';'stw';'stx';'sty';'svd';'svx';'sw';'swa';'swav';'sxt';'syh';'syn';'syw';'syx';'tak';'td0';'tfmx';'tg';'thx';'tm2';
            'tm8';'tmc';'toc';'trak';'tsp';'tta';'tun';'txw';'u';'u8';'uax';'ub';'ulaw';'ult';'ulw';'uni';'usf';'usflib';'ust';'uw';'uwf';'v2m';'vag';'val';
            'vap';'vb';'vc3';'vdj';'vgm';'vgz';'vlc';'vmd';'vmf';'vmo';'voc';'voi';'vox';'voxal';'vpl';'vpm';'vpw';'vqf';'vrf';'vsq';
            'vtx';'vyf';'w01';'w64';'wand';'wav';'wave';'wax';'wem';'wfb';'wfd';'wfm';'wfp';'wma';'wow';'wpk';'wpp';'wproj';'wrk';'wtpl';'wtpt';'wus';'wut';'wv';'wvc';'wve';'wwu';'wyz';'xa';'xfs';'xi';'xm';'xmf';'xmi';'xmz';'xp';'';'xrns';'';'xsp';'xspf';'xt';
            'xwb';'ym';'yookoo';'zab';'zpa';'zpl';'zvd';'zvr'
            %%flashPlayerFiles
            'dfxp'; 'f4a'; 'f4b'; 'f4p'; 'f4v'; 'fla'; 'flv'; 'fpb'; 'heu'; 'sol'; 'spl'; 'svg'; 'swf'; 'swf2'; 'swfl'; 'swl'; 'swz'; 'viewlet'; 'vp6'; 'x32'
            %%videoFiles
            '264';'3g2';'3gp';'3gp2';'3gpp2';'3mm';'3p2';'60d0';'89';'aaf';'aec';'aepx';'';'aetx';'ajp';'am';'amc';'amv';'amx';'aqt';'arcut';'arf';'asf';'asx';'avb';'avc';
            'avchd';'avd';'avi';'avp';'avs';'avv';'awlive';'axm';'bdm';'bdmv';'bdt2';'bdt3';'bik';'';'bix';'bmc';'bmk';'bnp';'box';'bs4';'bsf';'bu';'bvr';'byu';'camproj';'camrec';
            'camv';'ced';'cel';'cine';'cip';'';'clpi';'cmmp';'cmmtpl';'cmproj';'cmrec';'cpi';'cst';'cvc';'cx3';'d2v';'d3v';'dash';'dat';'dav';'db2';'dce';'dck';'dcr';'ddat';'dif';
            'dir';'divx';'dlx';'dmb';'dmsd';'dmsd3d';'dmsm';'dmsm3d';'dmss';'dmx';'dnc';'dpa';'dpg';'dream';'dsy';'dv';'dv-avi';'dv4';'dvdmedia';'dvr';'dvr-ms';'dvx';'dxr';'dzm';
            'dzp';'dzt';'edl';'evo';'eye';'ezt';'f4f';'f4p';'f4v';'fbr';'fbz';'fcp';'fcproject';'ffd';'flc';'flh';'fli';'flv';'flx';'ftc';'gcs';'gfp';'gl';'gom';'grasp';'gts';'gvi';
            'h264';'hdv';'hkm';'ifo';'imovieproj';'imovieproject';'inp';'int';'ircp';'irf';'ism';'ismc';'ismclip';'ismv';'iva';'ivf';'ivr';'ivs';'izz';'izzy';'jmv';'jss';'jts';'jtv';
            'k3g';'kdenlive';'kmv';'ktn';'lrec';'lrv';'lsf';'lsx';'lvix';'m15';'m1pg';'m1v';'m21';'m2a';'m2p';'m2t';'m2ts';'';'m4e';'m4u';'m4v';'m75';'mani';'meta';'mgv';'mj2';'mjp';'mjpg';
            'mk3d';'mkv';'mmv';'mnv';'mob';'mod';'modd';'moff';'moi';'moov';'mov';'movie';'mp21';'mp2v';'mp4';'mp4';'infovid';'mp4v';'mpe';'mpeg';'mpeg1';'mpeg4';'mpf';'mpg';'mpg2';
            'mpgindex';'mpl';'mpls';'mpsub';'mpv';'mpv2';'mqv';'msdvd';'mse';'msh';'mswmm';'mts';'mtv';'mvb';'mvc';'mvd';'mve';'mvex';'mvp';'mvy';'mxf';'mxv';'mys';'';'nsv';'nut';'nuv';'nvc';
            'ogm';'ogv';'ogx';'orv';'osp';'otrkey';'pac';'par';'pds';'pgi';'photoshow';'piv';'pjs';'playlist';'plproj';'pmf';'pmv';'pns';'ppj';'prel';'pro';'pro4dvd';'pro5dvd';'proqc';
            'prproj';'prtl';'psb';'psh';'pssd';'pva';'pvr';'pxv';'qt';'qtch';'qtindex';'qtl';'qtm';'qtz';'r3d';'rcd';'rcproject';'rdb';'rec';'rm';'rmd';'rmp';'rms';'rmv';'rmvb';'roq';'rp';
            'rsx';'rts';'rum';'rv';'rvid';'rvl';'sbk';'sbt';'scc';'scm';'scn';'screenflow';'sdv';'sec';'sedprj';'seq';'sfd';'sfvidcap';'siv';'smi';'smil';'smk';'sml';'smv';'snagproj';
            'spl';'sqz';'srt';'ssf';'ssm';'stl';'str';'stx';'svi';'swf';'swi';'swt';'tda3mt';'tdt';'tdx';'thp';'tid';'tivo';'tix';'tod';'tp';'tp0';'tpd';'tpr';'trp';'ts';'tsp';'ttxt';'tvs';'usf';
            'usm';'vbc';'vc1';'vcpf';'vcr';'vcv';'vdo';'vdr';'vdx';'veg';'vem';'vep';'vf';'vft';'vfw';'vfz';'vgz';'vid';'video';'viewlet';'viv';'vivo';'vix';'vlab';'vob';'vp3';'vp6';'vp7';'vpj';
            'vro';'vs4';'vse';'vsp';'w32';'wcp';'webm';'wlmp';'wm';'wmd';'wmmp';'wmv';'wmx';'wot';'wp3';'wpl';'wtv';'wve';'wvx';'xej';'xel';'xesc';'xfl';'xlmv';'xmv';'xvid';'y4m';'yog';'yuv';'zeg';'zm1';'zm2';'zm3';'zmv'
             };
SelectedType=lower(SelectedType);
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);%Consequative requests in sessions' i
    Temp=strfind(File(RequestNumbers),'/');
    % File Place: '/.../.../'+FileName . Filetyp
    for j=1:numel(RequestNumbers)
        Temp2=Temp{j,1};
        Directory=str2mat(File(RequestNumbers(j)));
        %Do not have file: Do not contain root and be just dirctory '/.../'
        if(numel(Temp2)==0 || length(Directory)<=Temp2(end)),continue,end
        FileType=Directory(Temp2(end)+1:end);
        Temp2=find(FileType=='.',1,'last');
        FileType=FileType(Temp2+1:end);
        if(sum(strcmp(FileType,SelectedType)))
            Feature(i,27)=Feature(i,27)+1;
        end
    end
    Feature(i,27)=(Feature(i,27)/numel(RequestNumbers))*100;
end

%% Feature 28: %Other
for i=1:SessionNumber
    AllCalculatedFiles=[21 22 23 27];
    Feature(i,28)=100-sum(Feature(i,AllCalculatedFiles));
end

%% Feature 29: %Post**
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,29)=(sum(strcmp(HttpMethod(RequestNumbers),'post'))/numel(RequestNumbers))*100;
end

%% Feature 30: %Get**
for i=1:SessionNumber
    RequestNumbers=find(SessionIndex==i);
    Feature(i,30)=(sum(strcmp(HttpMethod(RequestNumbers),'get'))/numel(RequestNumbers))*100;
end

%% Feature 31: Label -> Robot:1 Human:0
%>>>> If Trap file request (Feature 1) equals one then it is robot
Feature(:,31)=Feature(:,1);
%>>>> if contain certain words in user agent then it is robot
RobotKeyWords={'OntoSpider';
'HKU WWW Robot';
'Occam';
'ObjectsSearch';
'explorersearch';
'NorthStar';
'Nomad';
'NHSEWalker';
'newscan';
'NetScoop';
'libwww';
'NetMechanic';
'NetCarta CyberPilot Pro';
'Nederland';
'Nederland.zoek';
'NDSpider';
'sharp-info-agent';
'MwdSearch';
'MuscatFerret';
'muninn';
'muncher';
'MSNBOT';
'Motor';
'Monster';
'Monster/vX.X.X -$TYPE ($OSTYPE)';
'MOMspider/1.00 libwww-perl/0.40';
'MOMspider';
'moget';
'udmsearch';
'MindCrawler';
'NEC-MeshExplorer';
'MerzScope';
'MediaFox';
'x.y';
'mattie';
'M/3.8';
'marvin';
'marvin/infoseek (marvin-team@webseek.de)';
'Magpie';
'WWWWorm';
'Lycos';
'logo.gif';
'Lockon';
'linkwalker';
'LinkScan Server/5.5 | LinkScan Workstation/5.5';
'LinkScan';
'Linkidator';
'legs';
'larbin ';
'LabelGrab';
'label-grabber';
'KO_Yappo_Robot/1.0.4(http://yappo.com/info/robot.html)';
'ko_yappo_robot';
'Kilroy';
'KDD-Explorer';
'Katipo';
'image.kapsi.net';
'jumpstation';
'JubiiRobot';
'JoeBot';
'Jobot';
'Jobot/0.1alpha libwww-perl/4.0';
'jobo';
'jeeves';
'Jeeves v0.05alpha (PERL';
'LWP';
'lglb@doc.ic.ac.uk)';
'v0.05alpha';
'jcrawler';
'JBot ';
'JavaBee';
'IsraeliSearch';
'Iron33/0.0';
'Iron33';
'irobot';
'I Robot';
'IAGENT';
'inspectorwww';
'greenpac';
'InfoSpiders';
'Infoseek Sidewinder';
'Infoseek ';
'Sidewinder';
'InfoSeek Robot';
'InfoSeek';
'Informant';
'IncyWincy';
'Mozilla 3.01 PBWF (Win95)';
'INGRID';
'gestaltIconoclast';
'IBM_Planetwide';
'Planetwide';
'iajaBot';
'Decontextualizer';
'HTMLgobble ';
'htdig';
'Hometown Spider Pro';
'Hometown';
'AITCSRobot';
'havIndex';
'Harvest';
'hambot';
'Gulper Web Bot 0.2.4 (www.ecsl.cs.sunysb.edu/~maxim/cgi-bin/Link/GulperBot)';
'gulper';
'Gulliver';
'Gromit';
'griffon';
'Grapnel';
'Googlebot';
'Golem';
'GetURL';
'gcreep';
'gazz';
'gammaSpider';
'FunnelWeb';
'Freecrawl';
'Robot du CRIM 1.0a';
'Mozilla/2.0 (compatible fouineur v2.0; fouineur.9bit.qc.ca)';
'fouineur';
'Fish-Search-Robot';
'KIT-Fireball/2.0 libwww/5.0a';
'KIT-Fireball';
'H?¤m?¤h?¤kki';
'fido/0.9 Harvest/1.4.pl2';
'fido';
'ESIRover ';
'ESI';
'Hazel''s Ferret Web hopper';
'hopper';
'FELIX IDE';
'FELIXIDE';
'Mozilla/4.0 (compatible: FDSE robot)';
'FDSE';
'fastcrawler';
'FastCrawler 3.0.X (crawler@1klik.dk) - http://www.1klik.dk';
'Evliya Celebi v0.151 - http://ilker.ulak.net.tr';
'esther';
'esculapio';
'EMC Spider';
'Emacs-w3';
'elfinbot';
'EIT-Link-Verifier-Robot';
'EbiNess';
'ecollector';
'LWP::';
'dwcp';
'DragonBot';
'downloadexpress';
'DNAbot';
'grabber';
'DIIbot';
'Digger';
'dienstspider';
'Deweb';
'DesertRealm.com; 0.2; [J];';
'desertrealm';
'desert realm';
'CydralSpider/X.X (Cydral Web Image Search; http://www.cydral.com/)';
'cydralspider';
'cyberspyder';
'Cusco';
'Internet Cruiser Robot';
'cosmos';
'root';
'Web Core';
'CoolBot';
'confuzzledbot';
'Confuzzledbot/X.X (+http://www.confuzzled.lu/bot/)';
'conceptbot';
'combine';
'CMC';
'cIeNcIaFiCcIoN.nEt Spider (http://www.cienciaficcion.net)';
'cIeNcIaFiCcIoN.nEt Spider';
'http://www.cienciaficcion.net';
'churl';
'christcrawler';
'Mozilla/4.0 (compatible; ChristCrawler.com';
'ChristCrawler@ChristCENTRAL.com)';
'Checkbot';
'Digimarc CGIReader';
'Digimarc';
'CGIReader';
'Cassandra';
'calif';
'Calif/0.6 (kosarev@tnps.net; http://www.tnps.dp.ua)';
'CACTVS Chemistry Spider';
'CACTVS';
'BSpider';
'ABCdatos BotLink';
'BotLink';
'Acme';
'ahoy';
'AlkalineBOT';
'anthill';
'appie';
'Arachnophilia';
'Arale';
'Araneo';
'AraybOt';
'ArchitextSpider';
'Aretha';
'Ariadne';
'arks';
'Mozilla/2.0 (compatible; Ask Jeeves/Teoma)';
'Teoma"';
'Ask Jeeves';
'ASpider';
'ATN_Worldwide';
'Atomz';
'AURESYS';
'BackRub';
'BaySpider';
'Big Brother';
'Bjaaland';
'BlackWidow';
'Die Blinde Kuh';
'Ukonline';
'borg-bot';
'boxseabot';
'Mozilla/3.01 (compatible;)';
'sitemap';
'DOcoMo';
'ichiro';
'Teoma';
'AskJeeves';
'TeomaBar';
'AskJeevesJapan';
'yacy';
'yacybot';
'YahooFeedSeekeræ FeedSeeker';
'Seeker';
'crawl';
'slurp';
'fetcher';
'GeoHasher';
'Hasher';
'Inktomi';
'Slurp Yahoo';
'KDDI-CA33 UP.Browser/6.2.0.10.4 (compatible; Y!J-SRD/1.0; http://help.yahoo.co.jp/help/jp/search/indexing/indexing-27.html)';
'KDDI-CA33 UP.Browser';
'KDDI-CA33 UP';
'nutch';
'Mediapartners';
'Content Parser';
'ysearch';
'infobot';
'Baiduspider';
'bixo-agent';
'bixo';
'bixocrawler';
'Mozilla/5.0 (compatible; Seesaa ';
'Seesaa slurp';
'crawling';
'nutchsearch';
'nutch search';
'Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Slurp/21.529; U; en) Presto/2.5.25 Version/10.54';
'Presto';
'yahoobot';
'hacktrickz';
'Slurpem';
'Slurpy';
'Swami';
'WebIndexer';
'Indexer';
'Y!J-BSC';
'Yahoo Mindset';
'Mindset';
'Yahoo Pipes';
'Pipes';
'Yahoo! Japan';
'Yahoo-MMAudVid';
'MMAudVid';
'MMCrawler';
'Yahoo-Test';
'YahooCacheSystem';
'CacheSystem';
'yahoodir';
'YahooExternalCache';
'YahooMobile';
'yahooseeker';
'YahooYSMcm';
'YebolBot';
'rssguide';
'http://help.yahoo.com/help/us/shop/merchant/)';
'LGEYahooNews';
'Mozilla/4.0 (compatible; MSIE 5.0; Windows 98; Yahoo V1.0)';
'babelfish';
'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98; Yahoo-1.0)';
'yahoo';
'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Yahoo-1.0; HomePage; TheFreeDictionary.com; SV1; .NET CLR 1.1.4322)';
'Mozilla/4.0 (hhjhj@yahoo.com)';
'hhjhj';
'Yahoo!';
'YahooFantasyBaseball';
'YahooMobile';
'YahooMobileMessenger';
'aramabeta';
'blackcrawl';
'baidu';
'heritrix';
'baiduboxapp';
'BaiduHD';
'ccypolo';
'Coolpad';
'DESAY_TS1018_TD';
'DESAY';
'Lynx';
'Amiga';
'baidubrowser';
'BaiduGame';
'baiduds';
'appengine';
'Apostrophe/0.2.1.93 (compatible) filecache';
'filecache';
'Aplix HTTP';
'Aplix';
'Apexoo';
'APACHE_KNACKER';
'Apache/2.2.2 (Windows Server 2008)';
'Apache';
'AntiOpensourceBot';
'antibot';
'Anti-XBOCT';
'AntBot';
'ant';
'AnswerChase';
'AnoProxy';
'Anonymous Proxy';
'Anonymous';
'Anon';
'AnnoMille';
'Anemone';
'AmorankSpider';
'webcrawler';
'Amoena';
'AmigaVoyager';
'Voyager';
'amibot';
'Altresium ';
'Amfibi';
'AltaVista';
'Allrati';
'allizoM';
'gzip(gfe) (via translate.google.com)';
'gzip(gfe)';
'Allesklar';
'all_web3 larbin';
'all_web3';
'larbin';
'AlienInvaders';
'GreenSkin';
'AlexionResearchBot';
'AlexfDownload';
'alexabot_cache';
'alexa';
'alert(/xss/)';
'Aleksika';
'alef';
'akv';
'Akregator';
'AKHBOT';
'ajSitemap';
'Aji%20Reader/2.5 CFNetwork/459 Darwin/10.0.0d3';
'AJakieToMaZnaczenie';
'AideRSS';
'AHTTPConnection';
'AHSHTTP_POST_R';
'AHSHTTP';
'Ahrefs';
'AGSC BREAKING OUT PENNY STOCKS Taiwan (+http://www.angusenergy.com) [ZSEBOT]';
'AgentName';
'again/1.0';
'agadine';
'agada';
'AESOP_com_SpiderMan';
'SpiderMan';
'Aeero';
'Advanced URL Catalog 2.x';
'adsense_media_scraper';
'scraper';
'admin.ru.net';
'ADmatX';
'AddLinkbuilding';
'Ad Muncher';
'ActiveWorlds';
'Active Whois';
'Whois';
'AcquiaCrawler';
'Acoon';
'ACME Corporation';
'acebookexternalhit';
'Ace Explorer';
'Accoona';
'Accelatech';
'RSSCrawler';
'AcadiaUniversityWebCensusClient';
'Aboundex';
'Abortion';
'abond';
'Aberja Checkomat';
'Aberja';
'Checkomat';
'ABCdatos';
'A-Online Search';
'A-Online';
'Red Hat';
'A-listed Tablet';
'LinkChecker';
'411.info';
'computerproblemboard';
'Platz im GIGA-Homepage-Award';
'4.1.0 Profile';
'360jinrong';
'ZipCommander';
'comAgent';
'12scripts';
'SmartLinksAddon';
'12345 MRA 5.6';
'12345 FirePHP';
'FirePHP';
'AutoPager';
'100pulse/1.0';
'0xSCANNER-INURL';
'0xSCANNER';
'pastebin';
'JDatabase';
'VelocityWebshots';
'Webshots';
'detectURL';
'CaretNail';
'nail';
'CaretByte';
'exec';
'sp_MSforeachtable';
'MSforeachtable';
'Spyder';
'?&gt;&lt;?php phpinfo(); ?&gt;';
'&lt;SCRIPT&gt;window.location=''http://txt2pic.com''&lt;/script&gt;';
'cookie';
'omnom';
'enigmagroup';
'&lt;script&gt;alert(33)&lt;/script&gt;';
'script';
'Hack';
'&';
'@=”';
'phpinfo';
'&lt';
'/usr/bss_miner/user_agents';
'usr';
'.NET Framework Test Client';
'Test Client';
'DIE-KRAEHE- META-SEARCH-ENGINE';
'die-kraehe.de';
'kmem';
'kernel_memory';
'yandex';
'&quot';
'bluegrasswildwater';
'best-home-based-business';
'176.102.38.77';
'entropysearch';
'unicodemap';
'185.31.161.36';
'{ :;}; /bin/';
'GimmeUSAbot';
'citeseerxbot';
'autokrawl';
'''); select';
'versionsofthebible';
'.versionsofthebible';
'%3Cscript%3Dalert(''helo'');%3C/script%3D';
'MarcusWalker';
'!Susie';
'Susie';
'sync2it';
'proxyDIRECT';
'proxy DIRECT.';
'Bot';
'robot';
'crawl';
'spider';
'survey';
'Preview';
'Ezooms';
'archive';
'facebook';
'@alexa';
'InternetSeer';
'scoutjet';
'Yahoo! Slurp';
'SimplePie';
'BingPreview';
'SiteLockSpider ';
'okhttp';
'curl';
'ips-agent';
'WWWC';
'wzindex';
'WWWW';
'wombat';
'WOLP';
'w3mir';
'wlm';
'hotwired';
'wired';
'whowhere';
'whatUseek';
'winona';
'wget';
'WebWatch';
'WebWalker';
'webwalk';
'webvac';
'Websnarf';
'webs';
'webreaper';
'Digimarc WebReader';
'WebQuest';
'WebMoose';
'Mirror';
'WebLinker';
'weblayers';
'T-H-U-N-D-E-R-S-T-O-N-E';
'Webinator';
'Webfoot ';
'WebFetcher';
'WebCopy';
'webcatcher';
'WebBandit';
'WWWWanderer ';
'Wanderer';
'crawlpaper';
'W3M2';
'x.xxx';
'w3index';
'VWbot_K';
'void-bot';
'v ision-search';
'Victoria';
'Verticrawlbot';
'Valkyrie';
'urlck';
'uptime';
'UCSD';
'TLSpider';
'TkWWW ';
'TitIn';
'TITAN';
'teoma_agent1 ';
'Templeton';
'TechBOT';
'dlw3robot';
'tarspider';
'Tarantula';
'Mozilla/3.0 (Black Widow v1.1.0; Linux 2.0.27; Dec 31 1997 12:25:00';
'http://www.sygol.com';
'Sven';
'suntek';
'suke';
'ssearcher100';
'searcher';
'Spry';
'SpiderView ';
'SpiderMan ';
'spiderline';
'SpiderBot';
'mouse.house';
'spider_monkey';
'Speedy Spider';
'Spanner';
'Solbot';
'snooper';
'ESISmartSpider';
'SLCrawler';
'aWapClient';
'skymob';
'SiteTech-Rover';
'Open Text Site Crawler';
'Site Valet';
'SimBot';
'sift';
'libwww-perl-5.41';
'Shai''Hulud';
'Shagseeker';
'SG-Scout';
'Senrigan';
'searchprocess';
'Search-AU';
'Mozilla/4.0 (Sleek Spider/1.2)';
'Scooter';
'SafetyNet ';
'RuLeS';
'Roverbot';
'Robozilla';
'robofox';
'RoboCrawl';
'ComputingSite';
'Robi';
'Robbie';
'road runner';
'roadrunner';
'RixBot ';
'rix';
'RHCS';
'Resume Robot';
'RBSE ';
'Raven';
'Python ';
'Getterrobo-Plus';
'straight FLASH!! GetterroboPlus 1.5';
'psbot';
'PortalBSpider';
'Poppi';
'PlumtreeWebAccessor';
'PGP-KA';
'pjspider';
'PortalJuice';
'html_analyzer';
'analyzer';
'Pioneer';
'Pimptrain';
'piltdownman';
'phpdig';
'Duppies';
'perlcrawler';
'Peregrinator';
'Pegasus';
'patric';
'ParaSite';
'pageboy';
'packrat ';
'Orbsearch';
'Openfind data gatherer';
'Openbot/3.0+(robot-response@openfind.com.tw;+http://www.openfind.com.tw/robot.html)';
'4anything';
'Sitemap';
'Generator';
'Aardvark';
'ABCdatos';
'Aberja';
'Accelatech';
'Accoona';
'Ack';
'AcoiRobot';
'Agent';
'SharewarePlazaFileCheckBot';
'Aipbot';
'Aladin';
'Aleksika';
'Alkaline';
'Allrati';
'AltaVista';
'amibot';
'AnnoMille';
'Arikus';
'Arquivo';
'ASAHA';
'Search Engine';
'Turkey';
'Asahina';
'Antenna';
'ask.24x';
'ASPSeek';
'ASSORT';
'Asterias';
'Atlocal';
'Attentio';
'Augurfind';
'Augurnfind';
'Autowebdir';
'AV Fetch';
'AVSearch';
'Axadine';
'Axmo';
'BabalooSpider';
'Baboom';
'BaiduImagespider';
'Balihoo';
'BarraHomeCrawler';
'albertof';
'Bdcindexer';
'BDFetch';
'BDNcentral';
'Beauty';
'Bebop';
'BigClique';
'BIGLOTRON';
'Bigsearch';
'BilgiBeta';
'Bilgi';
'BilgiBot';
'Bitacle';
'Bitacle';
'Bee';
'Blitz';
'BlitzBOT';
'BlogBot';
'Bloglines';
'Blogpulse';
'BlogPulseLive';
'BlogSearch';
'Blogsearchbot';
'pumpkin';
'BlogsNowBot';
'BlogVibeBot';
'blogWatcher';
'BlogzIce';
'BloobyBot';
'Bloodhound';
'Boitho';
'BPImageWalker';
'BravoBrian';
'SpiderEngine';
'MarcoPolo';
'BruinBot';
'BSDSeek';
'BTbot';
'BuildCMS';
'BullsEye';
'Bumblebee';
'BurstFind';
'Buscaplus Robi';
'Robi';
'Carleson';
'Carnegie_Mellon_University';
'Catall Spider';
'CazoodleBot';
'CCBot';
'Ccubee';
'Ceramic Tile Installation Guide';
'floorstransformed';
'Cfetch';
'CipinetBot';
'cipinet';
'ClariaBot';
'Claymont';
'CloakDetect';
'fulltext';
'Clushbot';
'Cogentbot';
'cogentsoftwaresolutions';
'Combine';
'Cometrics';
'Computer_and_Automation_Research_Institute';
'sztaki';
'Comrite';
'Convera Internet';
'ConveraCrawler';
'ConveraMultiMediaCrawler';
'authoritativeweb';
'CoolBot';
'Cosmos';
'CougarSearch';
'Covac';
'TexAs';
'Arachbot';
'Cowbot';
'CrawlerBoy';
'Crawllybot';
'CreativeCommons';
'CrocCrawler';
'csci_b659';
'Cuasarbot';
'spider_beta';
'Cuasar';
'CurryGuide';
'SiteScan';
'Custom Spider';
'bisnisseek';
'CyberPatrol';
'SiteCat';
'Webbot';
'Cydral Web Image Search';
'CydralSpider';
'Cydral Image Search';
'Dmoz Downloader';
'DataFountains';
'DMOZ Feature Vector Corpus Creator';
'DataparkSearch';
'DataSpear';
'DataSpearSpiderBot';
'DatenBot';
'DaviesBot';
'Daypopbot';
'dbDig';
'dCSbot';
'de.searchengine';
'Deepak';
'DeepIndex';
'DeepIndexer';
'Denmex';
'websearch';
'dev-spider2';
'DiaGem';
'Diamond';
'DiamondBot';
'Digger';
'DigOut4U';
'DIIbot';
'DittoSpyder';
'Dloader';
'Dodgebot';
'Download-Tipp';
'Linkcheck';
'Drecombot';
'dtSearchSpider';
'DuckDuckBot';
'Dumbot';
'e-sense';
'e-SocietyRobot';
'eApolloBot';
'EARTHCOM';
'EasyDL';
'EchO';
'Egothor';
'EgotoBot';
'Ejupiter';
'Elfbot';
'ELI/20070402:2.0';
'EMPAS_ROBOT';
'EnaBot';
'Enfish Tracker';
'Enterprise_Search';
'Envolk';
'envolk[ITS]spider';
'EroCrawler';
'ES.NET_Crawler';
'eseek-larbin';
'ESISmartSpider';
'eStyleSearch';
'Eurobot';
'EvaalSE';
'Eventax';
'Everest-Vulcan';
'Exabot/3.0';
'Exactseek';
'Exalead NG';
'MimeLive';
'Excalibur';
'Execrawl';
'Exooba';
'ExperimentalHenrytheMiragoRobot';
'EyeCatcher';
'Factbot';
'Fast Crawler';
'Gold Edition';
'FAST Enterprise';
'FAST FirstPage';
'retriever';
'FAST MetaWeb';
'helpdesk';
'Fast PartnerSite';
'FAST-WebCrawler';
'Fastbot';
'FastBug';
'FastSearch';
'Favcollector';
'Favo';
'Faxobot';
'Feed Seeker Bot';
'Feed24';
'FeedChecker';
'feedfetcher';
'FeedDiscovery';
'FeedHub';
'MetaDataFetcher';
'Feedjit';
'Favicon';
'Mixcat';
'Trap Door';
'Findexa';
'gulesider';
'wortschatz';
'findlinks';
'FineBot';
'Firefly';
'kastaneta';
'naparek.cz';
'FirstGov';
'Firstsbot';
'Flapbot';
'flaptor';
'Flexum';
'FlickBot';
'RPT-HTTPClient';
'Flunky';
'FnooleBot';
'fnoole';
'FocusedSampler';
'Folkd';
'Fooky';
'ScorpionBot';
'ScoutOut';
'Francis';
'neomo';
'FreeFind';
'SiteSearchEngine';
'freefind';
'spiderinfo';
'FreshNotes';
'FTB-Bot';
'findthebest';
'FuseBulb';
'FyberSpider ';
'BeamMachine';
'CoBITSProbe';
'Expired Domain Sleuth';
'Filangy';
'Fileboost';
'FindAnISP';
'ISP';
'Finder';
'collage.cgi';
'DTAAgent';
'UnChaosBot';
'Chaos';
'sygol';
'+SitiDi';
'SitiDiBot';
'-DIE-KRAEHE- META-SEARCH-ENGINE';
'die-kraehe';
'192.com';
'Agent';
'4anything';
'neofonie';
'loesungen';
'A-Online Search';
'www.micro-sys.dk';
'products';
'sitemap-generator';
'miggibot';
'Abacho';
'xx.xxx';
'#BBL';
'Accoona-AI-Agent';
'aicrawler';
'accoonabot';
'ackerm';
'Acoi';
'Non-Profit';
'isara';
'acorn';
'AESOP';
'SpiderMan';
'Agadine';
'Agent-SharewarePlazaFile';
'SharewarePlaza';
'AgentName';
'Aipbot';
'Aleksika';
'perl';
'AltaVista';
'evreka';
'Amfibi';
'AnnoMille';
'AnswerBus';
'Anzwers';
'Aport';
'walhello';
'ArabyBot';
'Arach';
'Arachnoidea';
'Architext';
'archive.org';
'Arikus';
'fccn';
'Asahina';
'libhina';
'libtime';
'ask.24x';
'AskAboutOil';
'Asked';
'epicurus';
'ASPSeek';
'xxpre';
'AVSearch';
'peter';
'turney';
'Axadine';
'axada';
'AxmoRobot';
'Axmo';
'Babaloo';
'Baboom';
'meta tags';
'BarraHome';
'BDFetch';
'Beautybot';
'uchoose';
'BebopBot';
'apassion4jazz';
'BigCliqueBOT';
'BIGLOTRON';
'GNU';
'enhancededge';
'nutch-agent';
'lucene';
'Blaiz';
'Bee';
'rawgrunt';
'tricus';
'Blog';
'Bloglines';
'icerocket';
'Blogsearchbot';
'BlogsNow';
'BlogVibe';
'titech';
'Rhodes';
'BloobyBot';
'Blooby';
'Bloodhound';
'bdbrandprotect';
'SpiderEngin';
'BruinBot';
'webarchive';
'relevare';
'Buscaplu';
'Amfibi''s';
'amfibi';
'Carnegie_Mellon_University_Research_WebBOT';
'PLEASE READ';
'Carnegie_Mellon_University';
'brgordon';
'Catall';
'Cazoodle';
'commoncrawl';
'Ccubee';
'Ceramic Tile Installation Guide';
'Cfetch';
'ChristCRAWLER';
'Claria';
'CloakDetect';
'seznam';
'Ajax';
'Clushbot';
'Hector';
'Clush';
'Peleus';
'Computer_and_Automation_Research_Institute';
'ilab';
'Internet Spider';
'ConveraMultiMedia';
'Cool';
'Xyleme';
'Cowbot';
'NHN';
'Convera';
'Pinpoint';
'crawlly';
'Csci';
'b659';
'Cuasarbot';
'Custom';
'Cydral';
'Image Search';
'Downloader';
'DMOZ';
'Feature Vector Corpus';
'Creator';
'DataSpearSpider';
'Daten';
'Davies';
'Daypopbot';
'comBot';
'Deepak';
'USC';
'ISI';
'Dev';
'DiaGem';
'DigOut4U';
'Disco';
'NaverRobot';
'Dodgebot';
'experimental';
'Download';
'Tipp';
'Drecom';
'dtSearchSpider';
'dtSearch';
'DuckDuck';
'Sense';
'SocietyRobot';
'eApolloBot';
'eApollo';
'EARTHCOM';
'EasyDL';
'EchO';
'EgotoBot';
'Egoto';
'Ejupiter';
'ELI';
'DAUM';
'Communications';
'EMPAS';
'Enfish';
'Feed Seeker';
'Feed24';
'Firstsbot';
'Flexum';
'Flick';
'HTTPClient';
'fnoole';
'addurl';
'scorpionbots';
'FreshNotes';
'FTB';
'FuseBulb';
'FyberSpider';
'BeamMachine';
'Collage';
'DTAAgent';
'Chaos';
'SitiDi';
'192.comAgent'};

RobotKeyWords=lower(RobotKeyWords);
for i=1:SessionNumber
    % Do not consider sessions which are recognized as robot one in
    % previous step
    if(Feature(i,31)==1),continue,end
    RequestNumbers=find(SessionIndex==i);
    for j=1:numel(RequestNumbers)
        Temp=regexp(cell2mat(UserAgent(RequestNumbers(j))),RobotKeyWords);
        for k=1:numel(RobotKeyWords)
            Temp2=Temp{k,1};
            if(numel(Temp2))
                Feature(i,31)=1;
                break
            end
        end
    end
end

%% Post process of Feature 31: Label -> Benign Robot:1 Malicious Robot:2
%>>>> if a robot contain certain words in user agent then it is Malicious robot
MaliciousRobotKeyWords={
'8484 Boston Project';
'Atomic_Email_Hunter';
'atSpider';
'autoemailspider';
'bwh3_user_agent';
'China Local Browse';
'ContactBot';
'ContentSmartz ';
'DataCha0s ';
'Dbrowse';
'Demo Bot';
'DSurf15a';
'Ebrowse';
'Educate Search';
'EmailSiphon';
'EmailSpider ';
'EmailWolf';
'ESurf15a';
'ExtractorPro';
'Franklin, Locator';
'FSurf15a';
'Full Web Bot';
'AmiTCP Miami, AmigaOS';
'Anonymizer';
'AnswerChase, PROve ';
'AnswerChase';
'AVSearch-2.0-fusionIdx, CompetitorWebSites ';
'bCentral, Billing, Post-Process ';
'BMCLIENT ';
'Bot mailto, craftbot';
'CamelHttpStream';
'Cancer Information and Support International ';
'CFNetwork';
'CheckUrl ';
'Chilkat, chilkatsoft, ChilkatHttpUA';
'CHttpClient, Open Text Corporation';
'Contact';
'Crawler ';
'Dart, Communications, PowerTCP ';
'dds explorer';
'DevComponents.com, HtmlDocument Object ';
'Doubanbot';
'Dr.Web, online scanner';
'libwww';
'Jakarta, Commons';
'Y!OASIS/TEST';
'libwww-perl';
'MOT, MPx220';
'MJ12bot';
'Nutch';
'cr4nk';
'\<';
'\>';
'\''';
'\$x0E';
'\%0A';
'\%0D';
'\%27';
'\%3C';
'\%3E';
'\%00';
'\@\$x';
'\!susie';
'\_irc';
'\_works';
'\+select\+';
'\+union\+';
'\&lt;\?';
'1\,\1\,1\,';
'3gse';
'4all';
'4anything';
'5\.1\;\ xv6875\)';
'59\.64\.153\.';
'85\.17\.';
'88\.0\.106\.';
'a\_browser';
'a1\ site';
'abac';
'abach';
'abby';
'aberja';
'abilon';
'abont';
'abot';
'accept';
'access';
'accoo';
'accoon';
'aceftp';
'acme';
'active';
'address';
'adopt';
'adress';
'advisor';
'agent';
'ahead';
'aihit';
'aipbot';
'alarm';
'albert';
'alek';
'alexa\ toolbar\;\ \(r1\ 1\.5\)';
'alltop';
'alma';
'alot';
'alpha';
'america\ online\ browser\ 1\.1';
'amfi';
'amfibi';
'anal';
'andit';
'anon';
'ansearch';
'answer';
'answerbus';
'answerchase';
'antivirx';
'apollo';
'appie';
'arach';
'archive';
'arian';
'aboutoil';
'asps';
'aster';
'atari';
'atlocal';
'atom';
'atrax';
'atrop';
'attrib';
'autoh';
'autohot';
'av\ fetch';
'avsearch';
'axod';
'axon';
'baboom';
'baby';
'back';
'bali';
'bandit';
'barry';
'basichttp';
'batch';
'bdfetch';
'beat';
'beaut';
'become';
'bee';
'beij';
'betabot';
'biglotron';
'bilgi';
'binlar';
'bison';
'bitacle';
'bitly';
'blaiz';
'blitz';
'blogl';
'blogscope';
'blogzice';
'bloob';
'blow';
'bord';
'bond';
'boris';
'bost';
'bot\.ara';
'botje';
'botw';
'bpimage';
'brand';
'brok';
'broth';
'browseabit';
'browsex';
'bruin';
'bsalsa';
'bsdseek';
'built';
'bulls';
'bumble';
'bunny';
'busca';
'busi';
'buy';
'bwh3';
'cafek';
'cafi';
'camel';
'cand';
'captu';
'casper';
'catch';
'ccbot';
'ccubee';
'cd34';
'ceg';
'cfnetwork';
'cgichk';
'cha0s';
'chang';
'chaos';
'char';
'char\(';
'chase\ x';
'check\_http';
'checker';
'checkonly';
'checkprivacy';
'chek';
'chill';
'chttpclient';
'cipinet';
'cisco';
'cita';
'citeseer';
'clam';
'claria';
'claw';
'cloak';
'clshttp';
'clush';
'coast';
'cmsworldmap';
'code\.com';
'cogent';
'coldfusion';
'coll';
'collect';
'comb';
'combine';
'commentreader';
'common';
'comodo';
'compan';
'compatible\-';
'conc';
'conduc';
'contact';
'control';
'contype';
'conv';
'cool';
'copi';
'copy';
'coral';
'corn';
'cosmos';
'costa';
'cowbot';
'cr4nk';
'craft';
'cralwer';
'crank';
'crap';
'crawler0';
'crazy';
'cres';
'cs\-cz';
'cshttp';
'cuill';
'CURI';
'curl';
'curry';
'custo';
'cute';
'cyber';
'cz3';
'czx';
'daily';
'dalvik';
'daobot';
'dark';
'darwin';
'data';
'daten';
'dcbot';
'dcs';
'dds\ explorer';
'deep';
'deps';
'detect';
'dex';
'diam';
'diavol';
'diibot';
'dillo';
'ding';
'disc';
'disp';
'ditto';
'dlc';
'doco';
'dotbot';
'drag';
'drec';
'dsdl';
'dsok';
'dts';
'duck';
'dumb';
'eag';
'earn';
'earthcom';
'easydl';
'ebin';
'echo';
'edco';
'egoto';
'elnsb5';
'email';
'emer';
'empas';
'encyclo';
'enfi';
'enhan';
'enterprise\_search';
'envolk';
'erck';
'erocr';
'eventax';
'evere';
'evil';
'ewh';
'exac';
'exploit';
'expre';
'extra';
'eyen';
'fang';
'fast';
'fastbug';
'faxo';
'fdse';
'feed24';
'feeddisc';
'feedfinder';
'feedhub';
'fetch';
'filan';
'fileboo';
'fimap';
'find';
'firebat';
'firedownload\/1\.2pre\ firefox\/3\.6';
'firefox\/0';
'firs';
'flam';
'flash';
'flexum';
'flicky';
'flip';
'fly';
'focus';
'fooky';
'forum';
'forv';
'fost';
'foto';
'foun';
'fount';
'foxy\/1\;';
'free';
'friend';
'frontpage';
'fuck';
'fuer';
'futile';
'fyber';
'gais';
'galbot';
'gbpl';
'gecko\/2001';
'gecko\/2002';
'gecko\/2006';
'gecko\/2009042316';
'gener';
'geni';
'geo';
'geona';
'geth';
'getr';
'getw';
'ggl';
'gira';
'gluc';
'gnome';
'go\!zilla';
'goforit';
'goldfire';
'gonzo';
'google\ wireless';
'gosearch';
'got\-it';
'gozilla';
'grab';
'graf';
'greg';
'grub';
'grup';
'gsa\-cra';
'gsearch';
'gt\:\:www';
'guidebot';
'guruji';
'gyps';
'haha';
'hailo';
'harv';
'hash';
'hatena';
'hax';
'head';
'helm';
'herit';
'heritrix';
'hgre';
'hippo';
'hloader';
'hmse';
'hmview';
'holm';
'holy';
'hotbar\ 4\.4\.5\.0';
'hpprint';
'href\s';
'httpclient';
'httpconnect';
'httplib';
'httrack';
'human';
'huron';
'hverify';
'hybrid';
'hyper';
'ia_archiver';
'iaskspi';
'ibm\ evv';
'iccra';
'ichiro';
'icopy';
'ics\)';
'ida';
'ie\/5\.0';
'ieauto';
'iempt';
'iexplore\.exe';
'ilium';
'ilse';
'iltrov';
'indexer';
'indy';
'ineturl';
'infonav';
'innerpr';
'inspect';
'insuran';
'intellig';
'interget';
'internet\_explorer';
'internet\x';
'intraf';
'ip2';
'ipsel';
'irlbot';
'isc\_sys';
'isilo';
'isrccrawler';
'isspi';
'jady';
'jaka';
'jam';
'jenn';
'jet';
'jiro';
'jobo';
'joc';
'jupit';
'just';
'jyx';
'jyxo';
'kash';
'kazo';
'kbee';
'kenjin';
'kernel';
'keywo';
'kfsw';
'kkma';
'kmc';
'know';
'kosmix';
'krae';
'krug';
'ksibot';
'ktxn';
'kum';
'labs';
'lanshan';
'lapo';
'larbin';
'leech';
'lets';
'lexi';
'lexxe';
'libby';
'libcrawl';
'libcurl';
'libfetch';
'libweb';
'light';
'linc';
'lingue';
'linkcheck';
'linklint';
'linkman';
'lint';
'list';
'litefeeds';
'livedoor';
'livejournal';
'liveup';
'lmq';
'loader';
'locu';
'london';
'lone';
'loop';
'lork';
'lth\_';
'lwp';
'mac\_f';
'magi';
'magp';
'mail\.ru';
'main';
'majest';
'mam';
'mama';
'mana';
'marketwire';
'masc';
'mass';
'mata';
'mvi';
'mcbot';
'mecha';
'mechanize';
'mediapartners';
'metadata';
'metalogger';
'metaspin';
'metauri';
'mete';
'mib\/2\.2';
'microsoft\.url';
'microsoft\_internet\_explorer';
'mido';
'miggi';
'miix';
'mindjet';
'mindman';
'miner';
'mips';
'mira';
'mire';
'miss';
'mist';
'mizz';
'mj12';
'mlbot';
'mlm';
'mnog';
'moge';
'moje';
'mooz';
'more';
'mouse';
'mozdex';
'mozilla\/0';
'mozilla\/1';
'mozilla\/4\.61\ \[en\]';
'mozilla\/firefox';
'mpf';
'msie\ 2';
'msie\ 3';
'msie\ 4';
'msie\ 5';
'msie\ 6\.0\-';
'msie\ 6\.0b';
'msie\ 7\.0a1\;';
'msie\ 7\.0b\;';
'msie6xpv1';
'msiecrawler';
'msnbot\-media';
'msnbot\-products';
'msnptc';
'msproxy';
'msrbot';
'musc';
'mvac';
'mwm';
'my\_age';
'myapp';
'mydog';
'myeng';
'myie2';
'mysearch';
'myurl';
'nag';
'name';
'naver';
'navr';
'near';
'netants';
'netcach';
'netcrawl';
'netfront';
'netinfo';
'netmech';
'netsp';
'netx';
'netz';
'neural';
'neut';
'newsbreak';
'newsgatorinbox';
'newsrob';
'newt';
'next';
'ng\-s';
'ng\/2';
'nice';
'nikto';
'nimb';
'ninja';
'ninte';
'nog';
'noko';
'nomad';
'norb';
'note';
'npbot';
'nuse';
'nutch';
'nutex';
'nwsp';
'obje';
'ocel';
'octo';
'odi3';
'oegp';
'offby';
'offline';
'omea';
'omg';
'omhttp';
'onfo';
'onyx';
'openf';
'openssl';
'openu';
'opera\ 2';
'opera\ 3';
'opera\ 4';
'opera\ 5';
'opera\ 6';
'opera\ 7';
'orac';
'orbit';
'oreg';
'osis';
'our';
'outf';
'owl';
'p3p\_';
'page2rss';
'pagefet';
'pansci';
'parser';
'patw';
'pavu';
'pb2pb';
'pcbrow';
'pear';
'peer';
'pepe';
'perfect';
'perl';
'petit';
'phoenix\/0\.';
'phras';
'picalo';
'piff';
'pig';
'pingd';
'pipe';
'pirs';
'plag';
'planet';
'plant';
'platform';
'playstation';
'plesk';
'pluck';
'plukkie';
'poe\-com';
'poirot';
'pomp';
'post';
'postrank';
'powerset';
'preload';
'privoxy';
'probe';
'program\_shareware';
'protect';
'protocol';
'prowl';
'proxie';
'proxy';
'psbot';
'pubsub';
'puf';
'pulse';
'punit';
'purebot';
'purity';
'pyq';
'pyth';
'query';
'quest';
'qweer';
'radian';
'rambler';
'ramp';
'rapid';
'rawdog';
'rawgrunt';
'reap';
'reeder';
'refresh';
'reget';
'relevare';
'repo';
'requ';
'request';
'rese';
'retrieve';
'rip';
'rix';
'rma';
'roboz';
'rocket';
'rogue';
'rpt\-http';
'rsscache';
'ruby';
'ruff';
'rufus';
'rv\:0\.9\.7\)';
'salt';
'sample';
'sauger';
'savvy';
'sbcyds';
'sbider';
'sblog';
'sbp';
'scagent';
'scan';
'scej\_';
'sched';
'schizo';
'schlong';
'schmo';
'scorp';
'scott';
'scout';
'scrawl';
'screen';
'screenshot';
'script';
'seamonkey\/1\.5a';
'search17';
'searchbot';
'searchme';
'sega';
'semto';
'sensis';
'seop';
'seopro';
'sept';
'sezn';
'seznam';
'share';
'sharp';
'shaz';
'shell';
'shelo';
'sherl';
'shim';
'shopwiki';
'silurian';
'simple';
'simplepie';
'siph';
'sitekiosk';
'sitescan';
'sitevigil';
'sitex';
'skam';
'skimp';
'skygrid';
'sledink';
'sleip';
'slide';
'sly';
'smag';
'smurf';
'snag';
'snapbot';
'snapshot';
'snif';
'snip';
'snoop';
'sock';
'socsci';
'sogou';
'sohu';
'solr';
'some';
'soso';
'spad';
'span';
'spbot';
'speed';
'sphere';
'spin';
'sproose';
'spurl';
'sputnik';
'spyder';
'squi';
'sqwid';
'sqworm';
'ssm\_ag';
'stack';
'stamp';
'statbot';
'state';
'steel';
'stilo';
'strateg';
'stress';
'strip';
'style';
'subot';
'such';
'suck';
'sume';
'sunos\ 5\.7';
'sunrise';
'superbot';
'superbro';
'supervi';
'surf4me';
'surfbot';
'survey';
'susi';
'suza';
'suzu';
'sweep';
'swish';
'sygol';
'synapse';
'sync2it';
'systems';
'szukacz';
'tagger';
'tagoo';
'tagyu';
'take';
'talkro';
'tamu';
'tandem';
'tarantula';
'tbot';
'tcf';
'tcs\/1';
'teamsoft';
'tecomi';
'teesoft';
'teleport';
'telesoft';
'tencent';
'terrawiz';
'test';
'texnut';
'thomas';
'tiehttp';
'timebot';
'timely';
'tipp';
'tiscali';
'titan';
'tmcrawler';
'tmhtload';
'tocrawl';
'todobr';
'tongco';
'toolbar\;\ \(r1';
'topic';
'topyx';
'torrent';
'track';
'translate';
'traveler';
'treeview';
'tricus';
'trivia';
'trivial';
'TRUE';
'tunnel';
'turing';
'turnitin';
'tutorgig';
'twat';
'tweak';
'twice';
'tygo';
'ubee';
'uchoo';
'ultraseek';
'unavail';
'unf';
'universal';
'unknown';
'upg1';
'urlbase';
'urllib';
'urly';
'user\-agent\:';
'useragent';
'usyd';
'vagabo';
'valet';
'vamp';
'vci';
'veri\~li';
'verif';
'versus';
'via';
'vikspider';
'virtual';
'visual';
'void';
'voyager';
'vsyn';
'w0000t';
'w3search';
'walhello';
'walker';
'wand';
'waol';
'watch';
'wavefire';
'wbdbot';
'weather';
'web\.ima';
'web2mal';
'webarchive';
'webbot';
'webcat';
'webcor';
'webcorp';
'webcrawl';
'webdat';
'webdup';
'webgo';
'webind';
'webis';
'webitpr';
'weblea';
'webmin';
'webmoney';
'webp';
'webql';
'webrobot';
'webster';
'websurf';
'webtre';
'webvac';
'webzip';
'wells';
'wep\_s';
'wget';
'whiz';
'widow';
'win67';
'windows\-rss';
'windows\ 2000';
'windows\ 3';
'windows\ 95';
'windows\ 98';
'windows\ ce';
'windows\ me';
'winht';
'winodws';
'wish';
'wizz';
'worio';
'works';
'world';
'worth';
'wwwc';
'wwwo';
'wwwster';
'xaldon';
'xbot';
'xenu';
'xirq';
'y\!tunnel';
'yacy';
'yahoo\-mmaudvid';
'yahooseeker';
'yahooysmcm';
'yamm';
'yand';
'yandex';
'yang';
'yoono';
'yori';
'yotta';
'yplus\';
'ytunnel';
'zade';
'zagre';
'zeal';
'zebot';
'zerx';
'zeus';
'zhuaxia';
'zipcode';
'zixy';
'zmao';
'zmeu';
'zune';
'black\ hole';
'webstripper';
'netmechanic';
'cherrypicker';
'emailcollector';
'emailsiphon';
'webbandit';
'emailwolf';
'extractorpro';
'copyrightcheck';
'crescent';
'sitesnagger';
'prowebwalker';
'cheesebot';
'teleportpro';
'miixpc';
'website\ quester';
'moget/2\.1';
'webzip/4\.0';
'websauger';
'webcopier';
'mister\ pix';
'webauto';
'thenomad';
'www-collector-e';
'libweb/clshttp';
'asterias';
'turingos';
'spanner';
'infonavirobot';
'harvest/1\.5';
'bullseye/1\.0';
'mozilla/4\.0\ \(compatible;\ bullseye;\ windows\ 95\)';
'crescent\ internet\ toolpak\ http\ ole\ control\ v\.1\.0';
'cherrypickerse/1\.0';
'cherrypicker\ /1\.0';
'webbandit/3\.50';
'nicerspro';
'microsoft\ url\ control\ -\ 5\.01\.4511';
'dittospyder';
'foobot';
'webmasterworldforumbot';
'spankbot';
'botalot';
'lwp-trivial/1\.34';
'lwp-trivial';
'wget/1\.6';
'bunnyslippers';
'microsoft\ url\ control\ -\ 6\.00\.8169';
'urly\ warning';
'wget/1\.5\.3';
'linkwalker';
'moget';
'humanlinks';
'linkextractorpro';
'offline\ explorer';
'mata\ hari';
'lexibot';
'web\ image\ collector';
'the\ intraformant';
'true_robot/1\.0';
'true_robot';
'blowfish/1\.0';
'jennybot';
'miixpc/4\.2';
'builtbottough';
'propowerbot/2\.14';
'backdoorbot/1\.0';
'tocrawl/urldispatcher';
'webenhancer';
'tighttwatbot';
'suzuran';
'vci\ webviewer\ vci\ webviewer\ win32';
'szukacz/1\.4';
'queryn\ metasearch';
'openfind\ data\ gathere';
'openfind';
'xenu\''s\ link\ sleuth\ 1\.1c';
'xenu''s';
'repomonkey\ bait\ &\ tackle/v1\.01';
'repomonkey';
'zeus\ 32297\ webster\ pro\ v2\.9\ win32';
'webster\ pro';
'erocrawler';
'linkscan/8\.1a\ unix';
'keyword\ density/0\.9';
'kenjin\ spider';
'cegbfeieh';
'BlackWidow';
'Bot mailto:craftbot@yahoo.com';
'ChinaClaw';
'Custo';
'DISCo';
'Download Demon';
'eCatch';
'EirGrabber';
'EmailSiphon';
'EmailWolf';
'Express WebPictures';
'ExtractorPro';
'EyeNetIE';
'FlashGet';
'GetRight';
'GetWeb!';
'Go!Zilla';
'Go-Ahead-Got-It';
'GrabNet';
'Grafula';
'HMView';
'Image Stripper';
'Image Sucker';
'InterGET';
'Internet Ninja';
'JetCar';
'JOC Web Spider';
'larbin';
'libghttp';
'LeechFTP';
'Mass Downloader';
'MIDown tool';
'Missigua';
'Mister PiX';
'Navroad';
'NearSite';
'NetAnts';
'NetSpider';
'Net Vampire';
'NetZIP';
'Octopus';
'Offline Explorer';
'Offline Navigator';
'PageGrabber';
'Papa Foto';
'pavuk';
'pcBrowser';
'RealDownload';
'ReGet';
'SiteSnagger';
'SmartDownload';
'SuperBot';
'SuperHTTP';
'Surfbot';
'tAkeOut';
'Teleport Pro';
'VoidEYE';
'Web Image Collector';
'Web Sucker';
'WebAuto';
'WebCopier';
'WebFetch';
'WebGo IS';
'WebLeacher';
'WebReaper';
'WebSauger';
'Website eXtractor';
'Website Quester';
'WebStripper';
'WebWhacker';
'WebZIP';
'Widow';
'WWWOFFLE';
'Xaldon WebSpider';
'curious';
'jakarta';
'kmccrew';
'    planetwork';
'pycurl';
'sucker';
'turnit';
'vikspid';
'\&lt';
'\+union';
'\+select';
'\$x0';
'g00g1e';
'siclab';
'spam';
'sqlmap';
'seekerspider';
'AESOP_com_SpiderMan';
'Alexibot';
'Anonymouse.org';
'asterias';
'attach';
'BackDoorBot';
'BackWeb';
'Baiduspider';
'BatchFTP';
'Bigfoot';
'Black.Hole';
'BlackWidow';
'BlowFish';
'Bot mailto:craftbot@yahoo.com';
'BotALot';
'Buddy';
'BuiltBotTough';
'Bullseye';
'BunnySlippers';
'Cegbfeieh';
'CheeseBot';
'CherryPicker';
'ChinaClaw';
'Collector';
'Copier';
'CopyRightCheck';
'cosmos';
'Crescent';
'Curl';
'Custo';
'DA';
'DISCo';
'DIIbot';
'DittoSpyder';
'Download';
'Download Demon';
'Download Devil';
'Download Wonder';
'Downloader';
'dragonfly';
'Drip';
'eCatch';
'EasyDL';
'ebingbong';
'EirGrabber';
'EmailCollector';
'EmailSiphon';
'EmailWolf';
'EroCrawler';
'Exabot';
'Express WebPictures';
'Extractor';
'EyeNetIE';
'FileHound';
'FlashGet';
'Foobot';
'flunky';
'FrontPage';
'GetRight';
'GetSmart';
'GetWeb!';
'Go!Zilla';
'Google Wireless Transcoder';
'Go-Ahead-Got-It';
'gotit';
'Grabber';
'GrabNet';
'Grafula';
'Harvest';
'hloader';
'HMView';
'httplib';
'HTTrack';
'humanlinks';
'ia_archiver';
'IlseBot';
'Image Stripper';
'Image Sucker';
'Indy Library';
'InfoNaviRobot';
'InfoTekies';
'Intelliseek';
'InterGET';
'Internet Ninja';
'Iria';
'Jakarta';
'JennyBot';
'JetCar';
'JOC';
'JustView';
'Jyxobot';
'Kenjin.Spider';
'Keyword.Density';
'larbin';
'LeechFTP';
'LexiBot';
'lftp';
'libWeb/clsHTTP';
'likse';
'LinkextractorPro';
'LinkScan/8.1a.Unix';
'LNSpiderguy';
'LinkWalker';
'lwp-trivial';
'LWP::Simple';
'Magnet';
'Mag-Net';
'MarkWatch';
'Mass Downloader';
'Mata.Hari';
'Memo';
'Microsoft.URL';
'Microsoft URL Control';
'MIDown tool';
'MIIxpc';
'Mirror';
'Missigua Locator';
'Mister PiX';
'moget';
'Mozilla/3.Mozilla/2.01';
'Mozilla.*NEWT';
'NAMEPROTECT';
'Navroad';
'NearSite';
'NetAnts';
'Netcraft';
'NetMechanic';
'NetSpider';
'Net Vampire';
'NetZIP';
'NextGenSearchBot';
'NG';
'NICErsPRO';
'NimbleCrawler';
'Ninja';
'NPbot';
'Octopus';
'Offline Explorer';
'Offline Navigator';
'Openfind';
'OutfoxBot';
'PageGrabber';
'Papa Foto';
'pavuk';
'pcBrowser';
'PHP version tracker';
'Pockey';
'ProPowerBot/2.14';
'ProWebWalker';
'psbot';
'Pump';
'QueryN.Metasearch';
'RealDownload';
'Reaper';
'Recorder';
'ReGet';
'RepoMonkey';
'RMA';
'Siphon';
'sitecheck.internetseer.com';
'SiteSnagger';
'SlySearch';
'SmartDownload';
'Snake';
'Snapbot';
'Snoopy';
'sogou';
'SpaceBison';
'SpankBot';
'spanner';
'Sqworm';
'Stripper';
'SuperBot';
'SuperHTTP';
'Surfbot';
'suzuran';
'Szukacz/1.4';
'tAkeOut';
'Teleport';
'Telesoft';
'TurnitinBot/1.5';
'The.Intraformant';
'TheNomad';
'TightTwatBot';
'Titan';
'toCrawl/UrlDispatcher';
'True_Robot';
'turingos';
'TurnitinBot';
'URLy.Warning';
'Vacuum';
'VCI';
'VoidEYE';
'Web Image Collector';
'Web Sucker';
'WebAuto';
'WebBandit';
'Webclipping.com';
'WebCopier';
'WebEMailExtrac.*';
'WebEnhancer';
'WebFetch';
'WebGo IS';
'Web.Image.Collector';
'WebLeacher';
'WebmasterWorldForumBot';
'WebReaper';
'WebSauger';
'WebSite';
'Website eXtractor';
'Website Quester';
'Webster';
'WebStripper';
'WebWhacker';
'WebZIP';
'Whacker';
'Widow';
'WISENutbot';
'WWWOFFLE';
'WWW-Collector-E';
'Xaldon';
'Xenu';
'Zeus';
'Zyborg';
'BlackWidow';
'Bot\ mailto:craftbot@yahoo.com';
'ChinaClaw';
'Custo';
'DISCo';
'Download\ Demon';
'EirGrabber';
'EmailSiphon';
'EmailWolf';
'Express\ WebPictures';
'ExtractorPro';
'EyeNetIE';
'FlashGet';
'GetRight';
'GetWeb!';
'Go!Zilla';
'Go-Ahead-Got-It';
'GrabNet';
'Grafula';
'HMView';
'HTTrack';
'Image\ Stripper';
'Image\ Sucker';
'Indy\ Library';
'InterGET';
'Internet\ Ninja';
'JOC\ Web\ Spider';
'JetCar';
'LeechFTP';
'MIDown\ tool';
'Mass\ Downloader';
'Mister\ PiX';
'Navroad';
'NearSite';
'NetAnts';
'NetSpider';
'NetZIP';
'Net\ Vampire';
'Octopus';
'Offline\ Explorer';
'Offline\ Navigator';
'PageGrabber';
'Papa\ Foto';
'ReGet';
'RealDownload';
'SiteSnagger';
'SmartDownload';
'SuperBot';
'SuperHTTP';
'Surfbot';
'Teleport\ Pro';
'TurnitinBot';
'VoidEYE';
'WWWOFFLE';
'WebAuto';
'WebCopier';
'WebFetch';
'WebGo\ IS';
'WebLeacher';
'WebReaper';
'WebSauger';
'WebStripper';
'WebWhacker';
'WebZIP';
'Web\ Image\ Collector';
'Web\ Sucker';
'Website\ Quester';
'Website\ eXtractor';
'Widow';
'Xaldon\ WebSpider';
'Zeus';
'archiverloader';
'casper';
'clshttp';
'cmsworldmap';
'curl';
'diavol';
'dotbot';
'eCatch';
'email';
'extract';
'flicky';
'grab';
'harvest';
'jakarta';
'java';
'kmccrew';
'larbin';
'libwww';
'miner';
'nikto';
'pavuk';
'pcBrowser';
'planetwork';
'pycurl';
'python';
'scan';
'skygrid';
'tAkeOut';
'wget';
'winhttp'
            };

MaliciousRobotKeyWords=lower(MaliciousRobotKeyWords);
for i=1:SessionNumber
    % Do not consider sessions which are recognized as human one in
    % previous steps
    if(Feature(i,31)==0),continue,end
    RequestNumbers=find(SessionIndex==i);
    for j=1:numel(RequestNumbers)
        Temp=regexp(cell2mat(UserAgent(RequestNumbers(j))),MaliciousRobotKeyWords);
        for k=1:numel(MaliciousRobotKeyWords)
            Temp2=Temp{k,1};
            if(numel(Temp2))
                Feature(i,31)=2;%Malicious Robot
                break
            end
        end
    end
end

%clearvars AllCalculatedFiles BrowserType DataVolume DateTime Directory ErrorCode FeatureNumber File FileList filename FileNumber FileType FirstDirectory FirstType Frequency HTML HTMLType HttpMethod i Image ImageType IntervalNumber j k Maximum Number NumberRequest Path pathname PPIFileList Referrer RequestNumbers RobotKeyWords SecondDirectory SecondType SelectedType SessionNumber Slashes Temp Temp2 Temp3 ZipType MaliciousRobotKeyWords 
%save(Name)
save(Name,'IP','UserAgent','Feature','SessionIndex')