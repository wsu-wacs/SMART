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


% Import log file to matlab with following format"
% LogFile format:
% IP'1'-'2'-'3'[...'4'-...]'5'HttpMethod'6'File'7'..."'8'ErroreCode'9'DataVolume'10'Referre

clc
clear
close all

[filename, pathname]=uigetfile({'*.*'},'Log file selector');
Path=[pathname filename];
%Name='DataTest';
Name=[filename 'Converted.mat'];
Name=[pathname '\' Name];
%filename = 'C:\Users\Zolfaghari\Desktop\SMART\ArticleBaz\A';
Nrows = numel(textread(Path,'%1c%*[^\n]'));
fileID = fopen(Path,'r');
i=0;

IP=cell(Nrows,1);
DateTime=cell(Nrows,1);
HttpMethod=cell(Nrows,1);
File=cell(Nrows,1);
ErrorCode=cell(Nrows,1);
DataVolume=cell(Nrows,1);
Referrer=cell(Nrows,1);
UserAgent=cell(Nrows,1);

while ~feof(fileID)
%for i=0:9
    i=i+1;
    line = fgets(fileID);
    Space=find(line==' ');
    IP{i}=line(1:Space(1)-1);
    DateTime{i}=line(Space(3)+2:Space(4)-1);
    HttpMethod{i}=line(Space(5)+2:Space(6)-1);
    File{i}=line(Space(6)+1:Space(7)-1);
    ErrorCode{i}=line(Space(8)+1:Space(9)-1);
    DataVolume{i}=line(Space(9)+1:Space(10)-1);
    Referrer{i}=line(Space(10)+2:Space(11)-2);
    UserAgent{i}=line(Space(11)+1:end);
end
fclose(fileID);
%clearvars filename fileID i line Space filename pathname Nrows Path
save(Name,'IP','DateTime','HttpMethod','File','ErrorCode','DataVolume','Referrer','UserAgent')